require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'rack/auth/basic'
require 'open-uri'

class RedmineGrackAuth < Rack::Auth::Basic

  def valid?(auth)
    url = $grackConfig[:redmine]
    return false if !url

    creds = *auth.credentials
    user, pass = creds[0, 2]

    identifier = get_project()
    return false if !identifier
    permission = (@req.request_method == "POST" && Regexp.new("(.*?)/git-receive-pack$").match(@req.path_info) ? 'rw' : 'r')

    begin
      open("#{url}grack/xml/#{identifier}/#{permission}", :http_basic_authentication => [auth.user, auth.pass]) {}
    rescue
      return false
    end

    return true
  end

  def call(env)
    @env = env  
    @req = Rack::Request.new(env)

    return unauthorized if(not defined?($grackConfig))
    return unauthorized if($grackConfig[:require_ssl_for_auth] && @req.scheme != "https")

    auth = Request.new(env)
    return unauthorized unless auth.provided?
    return bad_request unless auth.basic?
    return unauthorized unless valid?(auth)

    env['REMOTE_USER'] = auth.username
    return @app.call(env)
  end

  def get_project
    paths = ["(.*?)/git-upload-pack$", "(.*?)/git-receive-pack$", "(.*?)/info/refs$", "(.*?)/HEAD$", "(.*?)/objects" ]

    paths.each {|re|
      if m = Regexp.new(re).match(@req.path)
        path = m[1];
        dir  = projPath.gsub(/^.*\//, "")
        identifier = projDir.gsub(/\.git$/, "")
        return (identifier == '' ? nil : identifier)
      end
    }

    return nil
  end

end
