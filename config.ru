use Rack::ShowExceptions

require './lib/git_http.rb'

config = {
  :project_root          => "/srv/git",
  :git_path              => '/usr/local/libexec/git-core/git',
  :upload_pack           => true,
  :receive_pack          => true,

# possible redmine auth
#  :use_redmine_auth      => true,
#  :require_ssl_for_auth  => true,
#  :redmine               => 'http://redmine.example.domain/'

#possible ldap auth
# required values
#  :use_ldap_auth         => true,
#  :ldap_host             => "ldap.example.com",
#  :ldap_base             => 'dc=example,dc=com'
# the following values are not required but listed here with their defaults
# don't require a group membership (default)
#  :ldap_require_groups   => false,
# can be one group
#  :ldap_require_groups   => 'test_group'
# or multiple groups
#  :ldap_require_groups   => ['test_group','git_access']
# only check for groups with a certain prefix
#  :ldap_group_prefix     => 'project_',
#  :ldap_port             => '636',
#  :ldap_encryption       => :simple_tls,
}


if config[:use_redmine_auth]
  $grackConfig = config
	require 'lib/redmine_grack_auth'
	use RedmineGrackAuth do |user,pass|
		false #dummy code, validation is done in module
	end
elsif config[:use_ldap_auth]
  require 'lib/ldap_grack_auth'
  use LdapGrackAuth do |user,pass|
    false #dummy code, validation is done in module
  end
end


run GitHttp::App.new(config)
