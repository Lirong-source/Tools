#!/bin/bash

home=$(dirname $(readlink -f "$0"))

filename=$home/output.csv
datadir=$home/nvd_data/patch
outputfile=$home/result.csv

if [ $# == 2 ];then
    outputfile=$1
    filename=$2
fi

#echo "outputfile=${outputfile}"
#echo "filename=${filename}"

cat $filename | while read line
do
    line=${line%?}
    dir="$datadir/$line"
    if [ -d "$dir" ]; then
        path=""
        grep -r -P '@@|\+\+\+ b'  $dir/*patch  | grep -P ' [0-9a-zA-Z_\*]+[\s]?\(|\+\+\+ [\S]+' -o | awk '{gsub(/^\s+\*|\($/, "");print}'  |while read str
        do
            if [[ "$str" =~ ^\+\+\+.* ]]; then            
                path=`echo $str | awk '{gsub(/^\+\+\+ b\//, "");print}'`
                #echo "path = $path"
            else
                if [[ "$path" =~ ^drivers\/ ]]; then
                    continue
                fi
        	echo -n "$line," >> $outputfile
                echo -n "$path," >> $outputfile
                echo -n "$str," >> $outputfile
		echo "" >> $outputfile
            fi
        done
    fi
done





