require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'rack/auth/basic'

require 'net/ldap'


class LdapGrackAuth < Rack::Auth::Basic
  
  def config
    @app.config
  end
  
  def valid?(auth)
    user, pass = auth.credentials[0,2]
    login = ldap_login(user,pass)
    login && check_basic_group_privs(login.first) && check_path_privs(login.first)
  end

  def call(env)
    @req = Rack::Request.new(env)
    auth = Request.new(env)
    
    result = nil
    result = unauthorized if result.nil? && !auth.provided?
    result = bad_request if result.nil? && !auth.basic?
    if result.nil?
      if valid?(auth)
        env['REMOTE_USER'] = auth.username
      else
        result = unauthorized
      end
      clean_up
      result.nil? ? @app.call(env) : result
    else
      result
    end
  end

  protected
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
    if required_permission == 'rw'
      access = false
      if @req.path_info =~  /^\/users\/(\w+)\/.+\/.+/
        access = check_user_privs(login,$1)
      elsif @req.path_info =~  /^\/(\w+)\/.+\/.+/
        access = check_project_privs(login,$1)
      end
      @app.allow_creation! if access      
    else
      # as we check basic ro access within the basic_group_privs
      # we need to return true if we don't want to write
      # also for an initial push we need to allow creation
      @app.allow_creation!
      access = true
    end
    access
  end
  
  def check_user_privs(login,user)
    user == login[:uid].first
  end
  
  def check_project_privs(login,project)
    groups.any?{|group| (group[:cn].first == config[:ldap_group_prefix].to_s + project) && member_in_group?(login,group)}
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
    @ldap = @groups = nil
  end
  
  def required_permission
    (@req.request_method == "POST" && Regexp.new("(.*?)/git-receive-pack$").match(@req.path_info) ? 'rw' : 'r')
  end
end
