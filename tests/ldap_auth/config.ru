$LOAD_PATH.unshift File.expand_path(File.dirname(__FILE__) + '/lib')

require 'lib/git_http'

config = {
  :project_root          => File.expand_path(File.join(File.dirname(__FILE__),'..')),
  :upload_pack           => true,
  :receive_pack          => true,

# possible redmine auth
#  :use_redmine_auth      => true,
#  :require_ssl_for_auth  => true,
#  :redmine               => 'http://redmine.example.domain/'

#possible ldap auth
   :use_ldap_auth         => true,
   :ldap_host             => "ldap.example.com",
# the following values are not required but listed here with their defaults
#  :ldap_require_groups   => false,
#  :ldap_require_groups   => 'test_group'
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
