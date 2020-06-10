#!/bin/bash


#   Description: According to SoftwareList.csv (e.g. Linux kernel 4.1), we search CVE dataset to find CVE IDs, that influence the targetSoftware.
#   The searching  results (CVE ID, function name, and file name) are stored in searchResults
#   Input: SoftwareList.csv
#        
#   Output: searchResults

home=$(dirname $(readlink -f "$0"))

# Input file
filename=$home/SoftwareList.csv


TmpDir=$home/software-Tmpoutput

if [ -d $TmpDir  ];then
    rm -r $TmpDir
fi

if [ ! -d $TmpDir  ];then
    mkdir $TmpDir
fi

outputdir=$home/searchResults

if [  -d $outputdir  ];then
    rm -r $outputdir
fi

if [ ! -d $outputdir  ];then
    mkdir $outputdir
fi
#   The first line of SoftwareList.csv is reserved
headflag=true
cat $filename | while read line
do
    if [ $headflag == true ]
    then
        headflag=false
        continue
    fi
    #   Obtain the name and version of the target software
    oriname=`echo $line |awk -F, '{print $1}'`  
    name=`echo $oriname | sed 's/[ ]*//g' | sed 's/[\/]/-/g'`
    version=`echo $line |awk -F, '{print $2}'`  


    #echo $name
    #echo $version

    #   Obtain CVE ID list that influence the target software, the temp results are stored in  software-Tmpoutput/name-version

    docker run -t --rm --privileged -v $home:/Linux_kernel_bugs -v $TmpDir:/tmp_dir -w /Linux_kernel_bugs  python:3.7 python cve.py ${name} ${version} /tmp_dir

    #   Deduplication, e.g. 4.1 is the same as 4.1.0
    foutput=$TmpDir/${name}-${version}
    sort -n $foutput | uniq > ./tmp
    sort -n ./tmp | uniq > $foutput
    rm ./tmp
    if [ ! -s $foutput ]; then
        rm $foutput
    else
    #   Obtain  CVE ID, function name, and file name. The searching results are stored in searchResults/name-version
        bash software-apply.sh ${outputdir}/${name}-${version}.tmp $TmpDir/${name}-${version}
        sort -n ${outputdir}/${name}-${version}.tmp 2>/dev/null | uniq > ${outputdir}/${name}-${version}
        if [ -f "${outputdir}/${name}-${version}.tmp" ]; then
            rm ${outputdir}/${name}-${version}.tmp
        fi

        if [ ! -s "${outputdir}/${name}-${version}" ]; then
            rm ${outputdir}/${name}-${version}
        fi
    fi
done
