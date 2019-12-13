# ProjCripto

### Para compilar o programa, correr os seguintes comandos na diretoria principal do projeto:
```
-cmake .
-make
-chmod u+x bash.sh
-chmod u+x exit.sh
```
### Para executar o programa:
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

