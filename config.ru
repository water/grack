use Rack::ShowExceptions

require './lib/git_http.rb'

config = {
  project_root:          "/tmp/git-repos",
  git_path:              "/opt/local/bin/git",
  upload_pack:           true,
  receive_pack:          true,

  use_kerberos_auth:     true,
}


if config[:use_kerberos_auth]
  use KerberosGrackAuth
end

run GitHttp::App.new(config)
