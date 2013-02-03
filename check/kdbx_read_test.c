#include <cx9r.h>
#include <stdio.h>

int main(void)
{
  FILE *f;
  ckpr_err err;

  f = fopen(TESTFILE, "r");
  if (f == NULL) return 1;

  if ((err = ckpr_init()) != CKPR_OK)
    goto cleanup;

  if ((err = ckpr_kdbx_read(f, "qwertyuiopqwertyuiop")) != CKPR_OK)
    goto cleanup;

 cleanup:

  if (fclose(f) != 0)
  {
    return 1;
  }

  return err;
}

