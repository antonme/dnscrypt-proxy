BEGIN			{
                    subcolor  = "\033[2m";
				            basecolor = "\033[0m";
          }

				{
                     print $4 |& cmd; 
                     
                     if(( cmd |& getline result )>0) 
                     {
                         if (split (result,arr,"\t")>1)
                         {
                             subname=arr[1];
                             basename=arr[2]
                         }
                         else 
                         {
                             subname=""
                             basename=result
                         }
                     }

                    if (length(subname""basename)>38)
                    subname=substr(subname,0,length(subname)-(length(subname""basename)-36))"~."
        }

                {color="0m"}
/CACHE_HIT/     {color="32m"}
/FORCED_CACHE/  {color="38;5;36m"}
/FETCH/         {color="38;5;75m"}
/PASS/          {color="33m"}
/SYNTH/         {color="36m"}
/ERROR/         {color="31m\033[1m"}
/SERVFAIL/      {color="31m"}
/REJECT/        {color="38;5;208m"}
/NXDOMAIN/      {color="90m"}
$6=="PREFETCH"  {$6="POSTFETCH"}

                {ms=int($7)}
                {mscolor="38;5;196m"}
ms<500          {mscolor="38;5;124m"}
ms<200          {mscolor="38;5;214m"}
ms<120          {mscolor="33m"}
ms<80           {mscolor="38;5;47m"}
ms<30           {mscolor="32m"}
ms<=2           {mscolor="32m\033[2m"}


{
  printf("%-23.23s] %-15s %50.50s   %-6s \033["color"%15s\033[0m \033["mscolor"%8s\033[0m %7d %17.15s\n",\
                                $1" "$2,$3,subcolor""subname""basecolor""basename"\033[0m",$5,$6,$7,$8,$9)
}