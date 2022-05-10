
_shodan(){
  local cur prev words cword
  _init_completion || return
  
  if [ $prev == "shodan" ]; then
    COMPREPLY=( $( compgen -W 'alert convert count data domain download
        honeyscore host info init myip org parse radar scan search stats 
        stream version' -- "$cur" ))
    return
  fi


  case ${COMP_WORDS[COMP_CWORD-2]} in
    convert)
      COMPREPLY=( $( compgen -W 'kml csv geo.json images xlsx' -- "$cur"))
      return
      ;;
    data)
      case $prev in
        list)
          COMPREPLY=( $( compgen -W '--dataset' -- "$cur"))
          return
          ;;
        download)
          COMPREPLY=( $( compgen -W '--chunksize -O --filename' -- "$cur"))
          return
          ;;
      esac
      ;;
    host)
      if [ $prev == "--format" ]; then
          COMPREPLY=( $( compgen -W 'pretty tsv' -- "$cur"))
          return
      fi
      ;;
    org)
      if [ $prev == "add" ] ; then
          COMPREPLY=( $( compgen -W '--silent' -- "$cur"))
          return
      fi
      ;;
    scan)
      case $prev in
        internet)
          COMPREPLY=( $( compgen -W '--quiet' -- "$cur"))
          return
          ;;
        submit)
          COMPREPLY=( $( compgen -W '--wait --filename --force --verbose' -- "$cur"))
          return
          ;;
      esac
      ;;
    alert)
      case $prev in
        domain)
          COMPREPLY=( $( compgen -W '--triggers' -- "$cur"))
          return
          ;;
        download)
          COMPREPLY=( $( compgen -W '--alert-id' -- "$cur"))
          return
          ;;
        export)
          COMPREPLY=( $( compgen -W '--filename' -- "$cur"))
          return
          ;;
        list)
          COMPREPLY=( $( compgen -W '--expired' -- "$cur"))
          return
          ;;
        stats)
          COMPREPLY=( $( compgen -W '--limit -O --filename' -- "$cur"))
          return
          ;;
      esac
      ;;
  esac


  case $prev in
    host)
      COMPREPLY=( $( compgen -W '--format --history -O --filename
                    -S --save -h --help' -- "$cur"))
      ;;
    domain)
      COMPREPLY=( $( compgen -W '-D --detail -S --save -H --history
                     -T --type -h --help' -- "$cur"))
      ;;
    org)
      COMPREPLY=( $( compgen -W 'add info remove' -- "$cur"))
      ;;
    myip)
      COMPREPLY=( $( compgen -W '-6 -ipv6' -- "$cur"))
      ;;
    convert)
      COMPREPLY=( $(compgen -f -- ${cur}) )
      ;;
    parse)
      COMPREPLY=( $( compgen -W '--color --no-color --fields -f --filters 
                     -O --filename --separator' -- "$cur"))
      ;;
    scan)
      COMPREPLY=( $( compgen -W 'internet list protocols status submit' -- "$cur"))
      ;;
    data)
      COMPREPLY=( $( compgen -W 'download list' -- "$cur"))
      ;;
    search)
      COMPREPLY=( $( compgen -W '--color --no-color --fields --limit
                     --separator' -- "$cur"))
      ;;
    stats)
      COMPREPLY=( $( compgen -W '--limit --facets -O --filename' -- "$cur"))
      ;;
    stream)
      COMPREPLY=( $( compgen -W '--streamer --fields --separator --datadir --asn
                     --alert --countries --custom-filters --ports --tags --vulns
                     --limit --compresslevel --timeout --color --no-color 
                     --quite' -- "$cur"))   
      ;;
    alert)
      COMPREPLY=( $( compgen -W 'clear create disable domain download enable export
                     import info list remove stats triggers' -- "$cur"))
      ;;
  esac
  
  return 0 
} && complete -F _shodan shodan

