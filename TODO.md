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
* Check if value from 'master' field is salt in validation 
