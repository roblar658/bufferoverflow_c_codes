#include <stdio.h>
#include <string.h>

#define BUF_SIZE 8

void autentiser(void) {
  volatile int tilgang =
      0; // volatile hindrer kompilatoren i å optimalisere den bort
  char buffer[BUF_SIZE];

  printf("Skriv inn passord: ");

  // Off-by-one: går fra 0 til 8 (totalt 9 iterasjoner)
  for (int i = 0; i <= BUF_SIZE; i++) {
    int c = fgetc(stdin);
    if (c == EOF || c == '\n') {
      buffer[i] = '\0';
      break;
    }
    buffer[i] = (char)c;
  }

  if (strcmp(buffer, "hemmelig") == 0) {
    tilgang = 1;
  }

  if (tilgang) {
    printf("Tilgang innvilget! (tilgang = %d)\n", tilgang);
  } else {
    printf("Avvist.\n");
  }
}

int main(void) {
  autentiser();
  return 0;
}
