# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.network "forwarded_port", guest: 80, host: 8080

   config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get upgrade
    apt-get install -y cpanminus pkg-config apache2 curl libjansson-dev libcurl4-openssl-dev vim git apache2-dev build-essential libgdbm-dev libperl-dev libssl-dev
   SHELL
end
