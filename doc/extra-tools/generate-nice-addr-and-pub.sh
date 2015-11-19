#!/bin/bash

cjdroute_file="../../cjdroute"

if [[ ! -x "$cjdroute_file" ]] ;then
	echo "First please build the file $cjdroute_file"
fi

echo "Generates peer with pubkey starting with given charracter X, and also ipv6 starting with fcX."
echo "so it is easy to stop in logs for example"
echo ""
echo "Tell me, what character X to look for? (e.g. 1 or 2... some characters like 'a' seem to never work, do NOT use that)"

read goal
goal_len=${#goal} 

if [[ $goal_len == 1 ]] ; then 
	echo "Ok looking for 1-character goal ($goal)";
elif [[ $goal_len == 2 ]] ; then 
	echo "Ok looking for 2-character goal ($goal). Warning this will take x256 times longer then looking for first key, around half-hour";
else
	echo "Goal of this length ($goal_len) is not supported. But it's trivial to hack this script. Though maybe you want to just have a nice ipv6 instead?"
	exit 1
fi

f="$HOME/cjdroute.conf" 
echo -e "\nThis will overwrite [$f].\nWrite text 'over' and press enter to confirm and continue, or ctrl-c to abort." 
read confirm 
if [[ "$confirm" != "over" ]] ; then exit 1 ; fi
	
echo "Searching..."
while true 
do 
	"$cjdroute_file" --genconf > "$f" 
	cat "$f" | grep publicKey | head -n 1 | grep "\"${goal}" || continue ;
  # found pubkey, doe ipv6 matched too?
	cat "$f" | grep "\"ipv6\"" | head -n 1 | grep "fc${goal}" || { echo "Almost, but ipv6 was wrong, trying again (please just wait longer)..." ; continue ;  }

	echo "OK, FOUND IT!" ; cat "$f" | egrep '"ipv6"|"publicKey"|"privateKey"' 
	break
done
