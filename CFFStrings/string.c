

#include "string.h"

#define ESCAPED_CHAR(c) ( (c) == 0x0D ? 'r' : ( (c) == 0x0A ? 'n' :  't' )  )
#define ISESCAPED(c)    ( (c) == 0x09 || (c) == 0x0A || (c) == 0x0D )
#define ASCII(c)        ( (c) < 0x7F && ((c) >= 0x20 || ISESCAPED((c)) ) )

int
string
(
    char* input,
    int   inputSize,
    int   offset,
    char  wide,
    char* string,
    int   stringLen,
    char* isWide
)
{
    int len         = 0;
    int retVal      = 0;

    if (0 == input || 0 == inputSize || 
        0 == string || 0 == stringLen || 
        offset >= inputSize - 1 || 0 == isWide)
    {

    }
    else
    {
        if (ASCII(input[offset]))
        {
            //bug here?.. will assume ascii.. and then skip valid wide char on next char..  consider 'KD.I.S.'
            //will never see 'D.I.S.'  :(
            if (wide && '\0' == input[offset + 1])
            {
                while ( len < stringLen -1      && 
                        offset < inputSize - 1  &&
                        ASCII(input[offset])    &&
                        '\0' == input[offset+1])
                {
                    if (ISESCAPED(input[offset]))
                    {
                        string[len] = '\\';
                        string[len + 1] = ESCAPED_CHAR(input[offset]);
                        len += 2;
                    }
                    else
                    {
                        string[len] = input[offset];
                        len++;
                    }
                    retVal++;
                    offset+=2;
                }
                *isWide = 1;
            }
            else if (!wide)
            {
                while ( len < stringLen - 1 &&
                        offset < inputSize  &&
                        ASCII(input[offset]))
                {
                    if (ISESCAPED(input[offset]))
                    {
                        string[len] = '\\';
                        string[len + 1] = ESCAPED_CHAR(input[offset]);
                        len += 2;
                    }
                    else
                    {
                        string[len] = input[offset];
                        len++;
                    }
                    retVal++;
                    offset++;
                }
                *isWide = 0;
            }
        }
    }

    return retVal++;
}