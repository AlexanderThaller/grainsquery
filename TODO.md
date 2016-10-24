* Remove lines beginning with # from productname when deserializing
* Validate if minion did return to salt call (Minion did not return in file)
* Validate if file of minion is empty
* Pass unparsable hosts to the cache somehow
* merge command and subcommands flags (command will overwrite subcommands flags)
  so something like this should still work `grainsquery -l debug report`)
* Move `warn.*` to `validate.*` so we can just do a false/true with good
  defaults
* Add validate.default so we can disable all and then only enable what we want
  to validate
* Allow to only report for example saltmasters or kernels to make viewing the
  existing options easier
* Put the salt_grains in the $XDG_DATA_HOME/grainsquery/salt_grains folder
* Add git init and git update commands to initially clone the repo or update the
  repo with the salt grains
* Move defaults for cli args to cli.yml
* Filter by a list of minions (multiple `-i`)
* Getip will get the carp ip which shoudnt happen also it gets 10.1.3.205
  instead for mgmg0 which is also wrong
* Roles subcommand that will print all available roles, realms, etc.
* Filter by saltversion and use semver to parse the version so we can do nice
  queries like version `2014.*` or something like that
