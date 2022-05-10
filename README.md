# Shodan completion

Completion script for [shodan-cli](https://github.com/achillean/shodan-python)

## Install 

```sh
cp shodan_completion.sh /usr/share/bash-completion/completions/shodan
# or 
sudo make
# or
curl -sk https://raw.githubusercontent.com/mmpx12/shodan_completion/shodan_completion.sh | \
  sudo tee -a /usr/share/bash-completion/completions/shodan
``` 

## TODO


- [ ] add hints for params
- [ ] join long and short same params (ex: -O,--output)
