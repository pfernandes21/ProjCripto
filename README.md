# ProjCripto

### Para compilar o programa, correr os seguintes comandos na diretoria principal do projeto:
```
cmake .
make
chmod u+x bash.sh
chmod u+x exit.sh
```
### Para executar o programa, correr o seguinte comando na diretoria principal do projeto:
```
./election [number of candidates] [number of voters] [number of trustees]
```

Existem 4 funções onde cada uma corresponde aos papéis na eleição:
- Administrador, que define e cria a eleição (Admin.cpp)
- Voter, que vota nos candidatos (Voter.cpp)
- Tally Official, que conta os votos encriptados e verifica a sua validade (Tally.cpp)
- Counter, desencripta a contagem final e anuncia o vencedor (Counter).

Para além disso existem duas diretorias que guardam alguma informação:
- Ballot, que guarda os votos
- Trustees, que guardam parte da chave privada da eleição até o counter a juntar e desencriptar o resultado da mesma.

## Election
O programa tem apenas um executável que por sua vez evoca todas as outras funções.
O Admin deve ser executado em primeiro lugar.
O Voter deve ser executado em segundo lugar e pode ser executado várias vezes, onde cada vez corresponde a 1 voto.
O Tally deve ser executado em terceiro lugar.
O Counter deve ser executado em quarto lugar.
(O Tally e Counter não requerem input do utilizador)

## Admin
1. Inserir credenciais para a criação da CA e do seu certificado
2. Inserir credenciais para a criação do certificado e chaves de cada votante
3.  Inserir password para encriptação da chave privada da eleição que será distribuida pelos Trustees

## Voter
1. Inserir o ID de votante
2. Inserir o ID do candidato a votar
3. Inserir o número de votos pretendidos para o candidato
4. Executar o 2 e 3 passos as vezes desejadas 

### Nota:
Para "refazer" a eleição sem criar todos os certificados novamente basta apagar os ficheiros:
- accumulator.txt
- allShares.txt
- decriptedPrivateKey.txt
- resultCandidate_X.txt
- signatureTemp.txt
- Counter/actualVoters.txt
E repôr o ficheiro Voter/id.txt a 0.
A partir daí é possível executar o programa a partir do Voter.
