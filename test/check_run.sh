#!/bin/bash

wd=$(pwd)
pay_request="lnbcrt2m1pju8yyypp5fw792f22sn3fkf7v6s9ts8qqp4pctwrxh2lngsjjd04meyqrqt6sdqqcqzpgxqyz5vqsp5hlfxjuve42lf8ha2unuhta2e3uxr9v37yvr72w7gwm3tllqj56ps9qyyssqjuu0dyg9eny69pcf5nfzax97sx8ewg2dhp05ucr3l3j9dqc7xcw8js7zhw0wz3yg55j8ykkw8hrpv7zvgkwuckhr6q3vsva5y8flf9cqatkpp3"

#output=$(./submissions/run.sh "$wd" "$wd/test/input.csv" "$pay_request" 500)

pay_request3="lnbcrt5u1pjm6rg2pp5k5zsnvpc7ssclkpen2lggkhyz4a80g92ft4cr4q5h8lu637wtdvqdqqcqzpgxqyz5vqsp5gvahr9wj6cnf7dun7shls9w445hsc6jhsfjr7pywrl66k8vrauks9qyyssq46c4xvws54tuew5a6gfy7cz7jdp3c0a209fn3npjm02yt87ful2jyck5vyurgu4pja3xhhswrs640gxdk64zr7pvma4cnl5werv2yscqgtda05"
#output=$(./submissions/run.sh "$wd" "$wd/test/input3.csv" "$pay_request3" 400)

pay_request4="lnbcrt1u1pjm6rsapp53eatgh8hn2taqevdxhhts8twta9zadjnkmldmycjdsp2rgjn4s4sdqqcqzpgxqyz5vqsp5lnqhfn280cpmt79k4wd396jsde7k43vsu2lsy3sx2y9ckt62lvrq9qyyssq9aqq6wws6gwdlypxjc6ga68943jld8x7lk4dmqt66xlh8tmcwn5se8r69m2egv47ls3hgdc0glk4ac6v7qwaees3ruafdemdpxaeyzsq6ax4un"
output=$(./submissions/run.sh "$wd" "$wd/test/input4.csv" "$pay_request4" 200)

# Check the exit status
if [ $? -eq 0 ]; then
    echo "BUILD CHECK PASSED: this **does not** mean your code is correct, it is just a minimal build check."
else
    echo "ERROR: The script exited with an error."
	echo "Run script output: $output"
fi
