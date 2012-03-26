require 'rack/auth/abstract/handler'
require 'rack/auth/abstract/request'
require 'rack/auth/basic'

class KerberosGrackAuth < Rack::Auth::Basic

  def valid?(auth)
    user, pass = auth.credentials[0,2]
    return true
    `echo "#{pass}" | kinit #{user} > /dev/null` && $?.to_i == 0
    # fixme, extremely easy to do injections!!
  end

  def call(env)
    @env = env
    @req = Rack::Request.new(env)

    auth = Request.new(env)
    return unauthorized unless auth.provided?
    return bad_request unless auth.basic?
    return unauthorized unless valid?(auth)

    env['REMOTE_USER'] = auth.username
    return @app.call(env)
  end

  # Could be useful
  def get_project
    paths = ["(.*?)/git-upload-pack$", "(.*?)/git-receive-pack$", "(.*?)/info/refs$", "(.*?)/HEAD$", "(.*?)/objects" ]

    paths.each {|re|
      if m = Regexp.new(re).match(@req.path)
        projPath = m[1];
        dir  = projPath.gsub(/^.*\//, "")
        identifier = dir.gsub(/\.git$/, "")
        return (identifier == '' ? nil : identifier)
      end
    }

    return nil
  end

end

# Demonstration on how a module could hook itself
$registeredPlugins ||= []
$registeredPlugins << KerberosGrackAuth

