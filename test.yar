rule test
{
  strings:
    $s1 = "111"
  
  condition:
    any of ($s*)
}