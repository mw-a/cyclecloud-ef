use_nodename_as_hostname = node.fetch(:pbspro, {}).fetch(:use_nodename_as_hostname, false) || node.fetch(:slurm, {}).fetch(:use_nodename_as_hostname, false)
if use_nodename_as_hostname
  node_prefix = node.fetch(:pbspro, {}).fetch(:node_prefix, node.fetch(:slurm, {}).fetch(:node_prefix, ""))

  domain = node.fetch(:dns, {}).fetch(:search_list, "").split(",")[0]
  # determine from CC?
  node_arrays = ["execute", "hpc", "login", "gpu"]
  num_nodes = 20

  lines = []
  for nodearray in node_arrays do
    (1..num_nodes).each do |instance|
      node = "#{node_prefix}#{nodearray}-#{instance}"
      lines << "#{node} #{node}.#{domain}"
    end
  end

  directory '/opt/nisp' do
    owner 'root'
    group 'root'
    mode '0755'
    action :create
  end

  file "/opt/nisp/nat.conf" do
    content "# managed by cyclecloud\n\n" + lines.join("\n") + "\n"
    mode "0644"
  end
end
