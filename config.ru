use Rack::ShowExceptions

require './lib/git_http.rb'

config = {
  project_root:          "/srv/git",
  git_path:              '/usr/local/libexec/git-core/git',
  upload_pack:           true,
  receive_pack:          true,
}


if defined? $registeredPlugins
  # To see how to use this, look at KerberosGrackAuth
  # And start rackup with arguments
  #
  # `--include lib --require kerberos_grack_auth.rb`
  #
  $registeredPlugins.each do |plugin|
    p plugin # So you see that it actually loads
    use plugin
  end
end

run GitHttp::App.new(config)
