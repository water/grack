use Rack::ShowExceptions

require './lib/git_http.rb'

config = {
  project_root:          "/srv/git",
  git_path:              '/usr/local/libexec/git-core/git',
  upload_pack:           true,
  receive_pack:          true,

  use_kerberos_auth:     true,
}


if config[:use_kerberos_auth]
  use KerberosGrackAuth
end

run GitHttp::App.new(config)
