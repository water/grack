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
    
    result = nil
    result = unauthorized if result.nil? && !auth.provided?
    result = bad_request if result.nil? && !auth.basic?
    if result.nil?
      if ['ro','rw'].include?(access=valid?(auth))
        env['REMOTE_USER'] = auth.username
      else
        if access == '404'
          result = [404, GitHttp::App::PLAIN_TYPE, ["Not Found"]]
        else
          result =  unauthorized
        end
      end
      clean_up
      result.nil? ? @app.call(env) : result
    else
      result
    end
  end

  protected

  def valid?(auth)
    user, pass = auth.credentials[0,2]
    login = ldap_login(user,pass)
    login && check_basic_group_privs(login.first) && check_path_privs(login.first)
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
    if @req.path_info =~  /^\/users\/([_a-z][-0-9_a-z]*)\/.+\/.+/
      permitted_access = check_user_privs(login,$1)
    elsif @req.path_info =~  /^\/([_a-z][-0-9_a-z]*)\/.+\/.+/
      permitted_access = check_project_privs(login,$1)
    end

    if permitted_access == 'ro' && required_permission == 'ro'
      git_path_exists? ? 'ro' : '404'
    elsif permitted_access == 'rw'
      @app.allow_creation!
      permitted_access
    else
      false
    end
  end
  
  def check_user_privs(login,user)
    (user == login[:uid].first) ? 'rw' : 'ro'
  end
  
  def check_project_privs(login,project)
    groups.any?{|group| (group[:cn].first == config[:ldap_group_prefix].to_s + project) && member_in_group?(login,group)} ? 'rw' : 'ro'
  end
  
  def check_group(login,group)
    (ldap_group = groups.first{|g| g[:cn].first == group }) && member_in_group?(login,ldap_group)
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
end
