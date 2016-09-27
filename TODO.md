* Remove lines beginning with # from productname when deserializing
* Validate if minion did return to salt call (Minion did not return in file)
* Validate if file of minion is empty
* Pass unparsable hosts to the cache somehow
* Parse trivago_applications field
* merge command and subcommands flags (command will overwrite subcommands flags)
  so something like this should still work `grainsquery -l debug report`)
