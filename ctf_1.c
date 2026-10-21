#include <stdio.h>
#include <string.h>

void sjekk_passord(void) {
  int tilgang_innvilget = 0;
  char buffer[8];

  printf("Skriv inn passord: ");
  // gets() sjekker ikke grensene til bufferet i det hele tatt
  gets(buffer);

  if (strcmp(buffer, "hemmelig") == 0) {
    tilgang_innvilget = 1;
  }

  if (tilgang_innvilget) {
    printf("Tilgang innvilget!\n");
  } else {
    printf("Feil passord!\n");
  }
}

int main(void) {
  sjekk_passord();
  return 0;
}
