name 'ef'
maintainer 's+c'
maintainer_email 'support@cyclecomputing.com'
license 'MIT'
description 'Configures EF Portal'
long_description 'Configures EF Portal'
version '1.0.0'
chef_version '>= 12.1' if respond_to?(:chef_version)

%w{ cvolume }.each {|c| depends c}
