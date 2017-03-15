Testing
-----------------
-   [Run tests](#runtests)
  *   [Docker](#docker)
  *   [Locally](#locally)
-   [Writing Tests](#writingtests)

## Run Tests <a name="runtests"></a>
### Docker  <a name="docker"></a>

#### Build Docker
```bash
docker build -t mod_perimeterx-test -t Dockerfile-test .
```
#### Run tests on Docker

```bash
docker run mod_perimeterx-test
```


### Locally (Ubuntu) <a name="locally"></a>

#### Installing Dependencies

##### cpanminus

```bash
apt-get install cpanminus
```

##### mod_perimeterx

    git clone https://github.com/PerimeterX/mod_perimeterx.git
    cd mod_perimeterx
    git submodule update --init --recursive
    cd ..

#### Apache 2

##### 2.4

    sudo apt-get install --assume-yes apache2-mpm-prefork apache2-utils apache2-dev

#### Perl dependencies

    cpanm --installdeps --notest .

#### Test scaffolding

    perl Makefile.PL -configure -httpd_conf t/setup/apache2.conf -src_dir /usr/lib/apache2/modules

#### Run tests

    ./t/TEST -v
    
## Writing Tests <a name="writingtests"></a>

TBD
