directory '/opt/nisp' do
  owner 'root'
  group 'root'
  mode '0755'
  action :create
end

licserv = cluster.scheduler
file "/opt/nisp/dcv-licserv" do
  # assume rlm on scheduler for now
  content "5053@#{licserv}"
  mode "0644"
end
