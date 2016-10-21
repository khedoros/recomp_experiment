/******************************************************************************
 *  Demonstration shell
 * this is part of the libdisasm project
 *
 * author: Dmitry Podgorny <pasis.ua@gmail.com>
 * version: alpha5
 * license: GPL
 *****************************************************************************/

#include "disasm.h"
#include "string.h"

#include <stdio.h>
#include <stdlib.h>

void usage(char *s) {

	printf("Usage: %s [OPTIONS]\n\nOPTIONS:\n  -i filename\n  -o filename\n  --use16\n  --use32\n  --org offset\n  --help\n", s);

}

int main(int argc, char **argv) {

	char	s[64];		// String (for output code)
	uint8	*code,		// to hold the binary itself
		*index,		// pointer to the current command
		*tmp;		// pointer to temporary storage
	int	len,		// file size
		ifindex = 0,	// index in argv of the input file
		ofindex = 0,	// index in argv of the output file
		i;
	uint	bit = USE32,
		offset = 0;

	FILE	*f, *of = NULL;

	//=====================================================================

	i = 1;		// index in argv
	while ( i < argc ) { //Process arguments in argv

		if ( !strcmp(argv[i], "--help") ) {//Print use, exit
			usage(argv[0]);
			return 0;
		} else

		if ( !strcmp(argv[i], "-i") ) { //Specify input file
			if ( i == argc - 1 ) { //If -i is the last option, print usage, because the filename argument is missing
				usage(argv[0]);
				return 2;
			}
			ifindex = ++i;
		} else

		if ( !strcmp(argv[i], "-o") ) { //Specify output file
			if ( i == argc - 1 ) {
				usage(argv[0]);
				return 2;
			}
			ofindex = ++i;
		} else

		if ( !strcmp(argv[i], "--use16") )
		    printf(" use16\n");
			bit = USE16;
		else
		if ( !strcmp(argv[i], "--use32") )
		    printf(" use32\n");
			bit = USE32;
		else

		if ( !strcmp(argv[i], "--org") ) { //Specify starting offset to read from the file
			if ( i == argc - 1 ) {
				usage(argv[0]);
				return 2;
			}
			offset = atoi(argv[++i]);
	        printf(" org 0x%x\n\n", offset);
		}

		else {
			usage(argv[0]);
			return 3;
		}

		i++;

	}

	//=====================================================================

    //Open the input and output files, get the size of the input, allocate space to store it

	if ( ( f = fopen(argv[ifindex], "rb") ) == NULL ) {
		fprintf(stderr, "error while opening file \"%s\"!\n", argv[ifindex]);
		return 2;
	}

	if ( ofindex ) //output file is optional
		if ( ( of = freopen(argv[ofindex], "w", stdout) ) == NULL ) {
			fprintf(stderr, "error while creating file \"%s\"!\n", argv[ofindex]);
			fclose(f);
			return 2;
		}

    //get binary filesize
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);


	index = code = (uint8 *) malloc(len + 8);// with a "reserve" )))

	fread(code, 1, len, f); //read "len" bytes from "f" to "code"
	fclose(f);

	//=====================================================================

    //index: current position in binary. 
    //code:  pointer to beginning of binary
    //len:   length of binary data
    
	while ( (uint) index < (uint) code + len ) { //While eof hasn't been reached:

        //s: output string buffer
        //bit: expected bitness of code
        //offset + ((uint...: current offset within the binary
		tmp = disasm(index, s, bit, offset + ( (uint) index - (uint) (code) ));
		if ( !tmp ) {
			fprintf(stderr, "error: unknown opcode!\nstring: 0x%x 0x%x 0x%x 0x%x 0x%x\n", *index++, *index++, *index++, *index++, *index);
			return 1;
		}
		printf("%s\n", s);
		index = tmp;
	}

	//=====================================================================

	free(code);
	if ( of != NULL )
		fclose(of);

	return 0;

}
