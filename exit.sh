#!/bin/bash
#Reset program diretories
rm -r Voter;
mkdir Voter;
rm -r Trustees;
mkdir Trustees;
rm -r Tally;
mkdir Tally;
mkdir Tally/Certs;
rm -r Counter;
mkdir Counter;
rm -r Ballot;
mkdir Ballot;
rm -r Admin;
mkdir Admin;
mkdir Admin/ElectionKeys;
mkdir Admin/Certs;
mkdir Admin/CA;
rm accumulator.txt;
rm allShares.txt;
rm decriptedPrivateKey.txt;
rm resultCandidate_*;
rm -rf resultCandidate_*;
rm signatureTemp.txt;