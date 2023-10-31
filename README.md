# roast-go

Golang implementation of FROST and ROAST in BIP-340 compliant form.

Supports extremely large groups;
on the test machine 501/1000 takes around 30 minutes to execute in the worst case
where 499 members are malicious and coordinate to cause maximum DoS.