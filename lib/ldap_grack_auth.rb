require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'rack/auth/basic'

require 'net/ldap'


class LdapGrackAuth < Rack::Auth::Basic
  
  def config
    @app.config
  end
  
  def call(env)
    @req = Rack::Request.new(env)
    auth = Request.new(env)
    
    if !auth.provided?
      unauthorized
    elsif !auth.basic?
      bad_request
    else
      result = if ['ro','rw'].include?(access=valid?(auth))
        env['REMOTE_USER'] = auth.username
        @app.call(env)
      else
        if access == '404'
          [ 404, GitHttp::App::PLAIN_TYPE, ["Not Found"] ]
        elsif access == '403'
           [ 403, GitHttp::App::PLAIN_TYPE, ['Access denied.'] ]
        else
          unauthorized
        end
      end
      clean_up
      result
    end
  end

  protected

  def valid?(auth)
    user, pass = auth.credentials[0,2]
    login = ldap_login(user,pass)
    (login && check_basic_group_privs(login.first)) ? check_path_privs(login.first) : '403'
  end

  def ldap_login(user,pass)
    ldap.bind_as(
      :base     => config[:ldap_base],
      :filter   => "uid=#{user}",
      :password => pass
    )
  end

  def ldap
    @ldap ||= Net::LDAP.new(
      :host       => config[:ldap_host],
      :port       => config[:ldap_port]||'636',
      :encryption => config[:ldap_encryption]||:simple_tls
    )   
  end
  
  def check_basic_group_privs(login)
    return true unless config[:ldap_require_groups]
    config[:ldap_require_groups].to_a.any?{|group| check_group(login,group) }
  end
  
  def check_path_privs(login)
    permitted_access = false
    if invalid_path_request?(items = @req.path_info.split('/').reject(&:empty?))
        permitted_access = '403'
    elsif user_path_request?(items)
        permitted_access = check_user_privs(login,items[1])
    else
        permitted_access = check_project_privs(login,items[0])
    end

    if permitted_access == 'ro' && required_permission == 'ro'
      permitted_access = git_path_exists? ? 'ro' : '404'
    elsif permitted_access == 'ro' && required_permission == 'rw'
      permitted_access = '403'
    elsif permitted_access == 'rw'
      @app.allow_creation!
    end
    permitted_access
  end
  
  def check_user_privs(login,user)
    (user == login[:uid].first) ? 'rw' : 'ro'
  end
  
  def check_project_privs(login,project)
    groups.any?{|group| (group[:cn].first == config[:ldap_group_prefix].to_s + project) && member_in_group?(login,group)} ? 'rw' : 'ro'
  end
  
  def check_group(login,group)
    (ldap_group = groups.find{|g| g[:cn].first == group }) && member_in_group?(login,ldap_group)
  end

  def member_in_group?(login,group)
    # my primary group? or member of that group?
    (login[:gidnumber].first == group[:gidnumber].first) || group[:memberuid].include?(login[:uid].first)
  end
  
  def groups
    @groups ||= ldap.search(:base => config[:ldap_base],:attributes => ['cn','gidNumber','memberUid'],:filter => '(objectClass=posixGroup)')
  end

  def clean_up
    @ldap = @groups = @git_path_exists = @git_rel_path = nil
  end
  
  def required_permission
    (@req.request_method == "POST" && Regexp.new("(.*?)/git-receive-pack$").match(@req.path_info) ? 'rw' : 'ro')
  end

  def git_path_exists?
    @git_path_exists ||= File.directory?(git_path)
  end

  def git_path
    return @git_path unless @git_path.nil?
    root = @app.config[:project_root] || `pwd`
    @git_path = File.expand_path(File.join(root, git_rel_path))
  end

  def git_rel_path
    @git_rel_path ||= GitHttp::App.match_routing(@req)[1]
  end

  # Decide whether this is an access to some lower path or directly
  # into the root of the storage folder
  def invalid_path_request?(items)
    (items.size < 3) ||
      (items[0] == 'users' && items.size < 4) ||
      (items[0] == 'users' && items[2] == 'info' && items[3] == 'refs') ||
        (items[1] == 'info' && items[2] == 'refs')
  end

  def user_path_request?(items)
    items[0] == 'users'
  end
end
