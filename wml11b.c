/* 
 * WML11b firmware tool v1.0.0
 *
 * This code is public domain.
 * 
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>


#define FLAG_NONE 0
#define FLAG_JOIN	1
#define FLAG_EXTRACT 2
#define FLAG_HEADER 4
#define FLAG_IMAGE 8
#define FLAG_CNE 16
#define FLAG_PRINT 32
#define FLAG_FIX 64

/* Don't rely on this */
#define HEADER_SIZE 116

#define ENDIAN_BIG 1
#define ENDIAN_LITTLE 0

#define CRC32_XINIT 0xFFFFFFFFL		/* initial value */
#define CRC32_XOROT 0xFFFFFFFFL		/* final xor value */

#define MINIMUM_CHECKSUM_LEN	 8
#define MAXIMUM_CHECKSUM_LEN	99

/* NAACCR 6.0 Specifications */
#define NAACCR_60_CHECKSUM_POS	942
#define NAACCR_60_CHECKSUM_LEN	10

struct firmware
{
	char ident[5];
	unsigned int flags;

	char timestamp[17];

	unsigned int   soft_id;
	unsigned short soft_mid;
	unsigned short soft_min;

	unsigned int hardcomp;

	unsigned int unknown1;
	unsigned int unknown2;

	unsigned int header_crc;

	unsigned int image_offset;		
	unsigned int image_load_offset; 

	unsigned int image_size;		
	unsigned int image_crc;	

	unsigned char nulls[16];

	unsigned int cne_offset;	
	unsigned int unknown4;

	unsigned int cne_size;

	unsigned int cne_crc;	

	/* Proper CRCs */
	unsigned int p_header_crc;
	unsigned int p_image_crc;
	unsigned int p_cne_crc;

	/* File names */
	char *header_file;
	char *image_file;
	char *cne_file;

	/* file data */
	char *header;
	char *image;
	char *cne;

	char *in_file;
	char *out_file;
};

/* For the CRC32 calculation */
unsigned long  crctable[256] =
{
	0x00000000L, 0x77073096L, 0xEE0E612CL, 0x990951BAL,
	0x076DC419L, 0x706AF48FL, 0xE963A535L, 0x9E6495A3L,
	0x0EDB8832L, 0x79DCB8A4L, 0xE0D5E91EL, 0x97D2D988L,
	0x09B64C2BL, 0x7EB17CBDL, 0xE7B82D07L, 0x90BF1D91L,
	0x1DB71064L, 0x6AB020F2L, 0xF3B97148L, 0x84BE41DEL,
	0x1ADAD47DL, 0x6DDDE4EBL, 0xF4D4B551L, 0x83D385C7L,
	0x136C9856L, 0x646BA8C0L, 0xFD62F97AL, 0x8A65C9ECL,
	0x14015C4FL, 0x63066CD9L, 0xFA0F3D63L, 0x8D080DF5L,
	0x3B6E20C8L, 0x4C69105EL, 0xD56041E4L, 0xA2677172L,
	0x3C03E4D1L, 0x4B04D447L, 0xD20D85FDL, 0xA50AB56BL,
	0x35B5A8FAL, 0x42B2986CL, 0xDBBBC9D6L, 0xACBCF940L,
	0x32D86CE3L, 0x45DF5C75L, 0xDCD60DCFL, 0xABD13D59L,
	0x26D930ACL, 0x51DE003AL, 0xC8D75180L, 0xBFD06116L,
	0x21B4F4B5L, 0x56B3C423L, 0xCFBA9599L, 0xB8BDA50FL,
	0x2802B89EL, 0x5F058808L, 0xC60CD9B2L, 0xB10BE924L,
	0x2F6F7C87L, 0x58684C11L, 0xC1611DABL, 0xB6662D3DL,
	0x76DC4190L, 0x01DB7106L, 0x98D220BCL, 0xEFD5102AL,
	0x71B18589L, 0x06B6B51FL, 0x9FBFE4A5L, 0xE8B8D433L,
	0x7807C9A2L, 0x0F00F934L, 0x9609A88EL, 0xE10E9818L,
	0x7F6A0DBBL, 0x086D3D2DL, 0x91646C97L, 0xE6635C01L,
	0x6B6B51F4L, 0x1C6C6162L, 0x856530D8L, 0xF262004EL,
	0x6C0695EDL, 0x1B01A57BL, 0x8208F4C1L, 0xF50FC457L,
	0x65B0D9C6L, 0x12B7E950L, 0x8BBEB8EAL, 0xFCB9887CL,
	0x62DD1DDFL, 0x15DA2D49L, 0x8CD37CF3L, 0xFBD44C65L,
	0x4DB26158L, 0x3AB551CEL, 0xA3BC0074L, 0xD4BB30E2L,
	0x4ADFA541L, 0x3DD895D7L, 0xA4D1C46DL, 0xD3D6F4FBL,
	0x4369E96AL, 0x346ED9FCL, 0xAD678846L, 0xDA60B8D0L,
	0x44042D73L, 0x33031DE5L, 0xAA0A4C5FL, 0xDD0D7CC9L,
	0x5005713CL, 0x270241AAL, 0xBE0B1010L, 0xC90C2086L,
	0x5768B525L, 0x206F85B3L, 0xB966D409L, 0xCE61E49FL,
	0x5EDEF90EL, 0x29D9C998L, 0xB0D09822L, 0xC7D7A8B4L,
	0x59B33D17L, 0x2EB40D81L, 0xB7BD5C3BL, 0xC0BA6CADL,
	0xEDB88320L, 0x9ABFB3B6L, 0x03B6E20CL, 0x74B1D29AL,
	0xEAD54739L, 0x9DD277AFL, 0x04DB2615L, 0x73DC1683L,
	0xE3630B12L, 0x94643B84L, 0x0D6D6A3EL, 0x7A6A5AA8L,
	0xE40ECF0BL, 0x9309FF9DL, 0x0A00AE27L, 0x7D079EB1L,
	0xF00F9344L, 0x8708A3D2L, 0x1E01F268L, 0x6906C2FEL,
	0xF762575DL, 0x806567CBL, 0x196C3671L, 0x6E6B06E7L,
	0xFED41B76L, 0x89D32BE0L, 0x10DA7A5AL, 0x67DD4ACCL,
	0xF9B9DF6FL, 0x8EBEEFF9L, 0x17B7BE43L, 0x60B08ED5L,
	0xD6D6A3E8L, 0xA1D1937EL, 0x38D8C2C4L, 0x4FDFF252L,
	0xD1BB67F1L, 0xA6BC5767L, 0x3FB506DDL, 0x48B2364BL,
	0xD80D2BDAL, 0xAF0A1B4CL, 0x36034AF6L, 0x41047A60L,
	0xDF60EFC3L, 0xA867DF55L, 0x316E8EEFL, 0x4669BE79L,
	0xCB61B38CL, 0xBC66831AL, 0x256FD2A0L, 0x5268E236L,
	0xCC0C7795L, 0xBB0B4703L, 0x220216B9L, 0x5505262FL,
	0xC5BA3BBEL, 0xB2BD0B28L, 0x2BB45A92L, 0x5CB36A04L,
	0xC2D7FFA7L, 0xB5D0CF31L, 0x2CD99E8BL, 0x5BDEAE1DL,
	0x9B64C2B0L, 0xEC63F226L, 0x756AA39CL, 0x026D930AL,
	0x9C0906A9L, 0xEB0E363FL, 0x72076785L, 0x05005713L,
	0x95BF4A82L, 0xE2B87A14L, 0x7BB12BAEL, 0x0CB61B38L,
	0x92D28E9BL, 0xE5D5BE0DL, 0x7CDCEFB7L, 0x0BDBDF21L,
	0x86D3D2D4L, 0xF1D4E242L, 0x68DDB3F8L, 0x1FDA836EL,
	0x81BE16CDL, 0xF6B9265BL, 0x6FB077E1L, 0x18B74777L,
	0x88085AE6L, 0xFF0F6A70L, 0x66063BCAL, 0x11010B5CL,
	0x8F659EFFL, 0xF862AE69L, 0x616BFFD3L, 0x166CCF45L,
	0xA00AE278L, 0xD70DD2EEL, 0x4E048354L, 0x3903B3C2L,
	0xA7672661L, 0xD06016F7L, 0x4969474DL, 0x3E6E77DBL,
	0xAED16A4AL, 0xD9D65ADCL, 0x40DF0B66L, 0x37D83BF0L,
	0xA9BCAE53L, 0xDEBB9EC5L, 0x47B2CF7FL, 0x30B5FFE9L,
	0xBDBDF21CL, 0xCABAC28AL, 0x53B39330L, 0x24B4A3A6L,
	0xBAD03605L, 0xCDD70693L, 0x54DE5729L, 0x23D967BFL,
	0xB3667A2EL, 0xC4614AB8L, 0x5D681B02L, 0x2A6F2B94L,
	0xB40BBE37L, 0xC30C8EA1L, 0x5A05DF1BL, 0x2D02EF8DL
};

unsigned long CalcCRC32(unsigned char *p, unsigned long reclen, unsigned long checksumpos, unsigned long checksumlen)
{
	unsigned long j;

	/* initialize value */
	unsigned long crc = CRC32_XINIT;

	/* process each byte prior to checksum field */
	for (j = 1; j < checksumpos; j++) 
	{
		crc = crctable[(crc ^ *p++) & 0xFFL] ^ (crc >> 8);
	}

	/* skip checksum position */
	j += checksumlen;
	p += checksumlen;

	/* process remaining bytes in record */
	while (j <= reclen) 
	{
		crc = crctable[(crc ^ *p++) & 0xFFL] ^ (crc >> 8);
		j++;
	}

	/* return XOR out value */
	return crc ^ CRC32_XOROT;
}

void parse_firmware_file(struct firmware *fw, char *filename)
{
	int fd, out;

	if (filename == NULL)
	{
		printf("No filename provided!\n");
		exit(EXIT_FAILURE);
	}

	if ((fd = open(filename, O_RDONLY)) == -1)
	{
		printf("Could not open %s\n",filename);
		exit(EXIT_FAILURE);
	}

	/* Assumed to work */
	if (read(fd, fw->ident, sizeof(fw->ident) - 1) < 4)
	{
		printf("File is too short to be a valid .bcd file <4 bytes\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(fw->ident,"bCoD"))
	{
		printf("File does not appear to be a valid .bcd file\n");
		exit(EXIT_FAILURE);
	}

	/* File *could* be mangled past here, but I don't care */  
	read(fd, (char *)&fw->flags, 4);

	read(fd, (char *)&fw->timestamp, sizeof(fw->timestamp)-1);

	fw->timestamp[sizeof(fw->timestamp)-1] = '\0';

	read(fd, (char *)&fw->soft_id,  4);
	read(fd, (char *)&fw->soft_min, 2);
	read(fd, (char *)&fw->soft_mid, 2);

	read(fd, (char *)&fw->hardcomp, 4);

	read(fd, (char *)&fw->unknown1, 4);
	read(fd, (char *)&fw->unknown2, 4);

	read(fd, (char *)&fw->header_crc, 4);

	read(fd, (char *)&fw->image_offset, 4);
	read(fd, (char *)&fw->image_load_offset, 4);

	read(fd, (char *)&fw->image_size, 4);
	read(fd, (char *)&fw->image_crc, 4);

	read(fd, (char *)&fw->nulls,16);
	read(fd, (char *)&fw->cne_offset, 4);
	read(fd, (char *)&fw->unknown4, 4);
	read(fd, (char *)&fw->cne_size, 4);
	read(fd, (char *)&fw->cne_crc, 4);

	if ((fw->header = malloc(fw->image_offset)) == NULL)
	{
		printf("Could not allocate memory to store header\n");
		exit(EXIT_FAILURE);
	}

	lseek(fd, 0, SEEK_SET);

	read(fd, fw->header, fw->image_offset);

	if ((fw->image = malloc(fw->image_size)) == NULL)
	{
		printf("Could not allocate memory to store header\n");
		exit(EXIT_FAILURE);
	}

	lseek(fd, fw->image_offset, SEEK_SET);
	read(fd, fw->image, fw->image_size);

	if ((fw->cne = malloc(fw->cne_size)) == NULL)
	{
		printf("Could not allocate memory to store CNE\n");
		exit(EXIT_FAILURE);
	}

	lseek(fd, fw->cne_offset, SEEK_SET);
	read(fd, fw->cne, fw->cne_size);

	close(fd);

	/* Do proper checksumming */
	/* zero out 4 bytes of header that contained hash */
	fw->header[44] = fw->header[45] = fw->header[46] = fw->header[47] = 0;

	fw->p_header_crc = CalcCRC32((unsigned char*)fw->header,96,0,0);
	fw->p_image_crc  = CalcCRC32((unsigned char*)fw->image,fw->image_size,0,0);
	fw->p_cne_crc    = CalcCRC32((unsigned char*)fw->cne,fw->cne_size,0,0);

	return;
}

void extract_firmware_file(struct firmware *fw)
{
	int out;

	if ((fw == NULL) || fw->image == NULL || fw->header == NULL || fw->cne == NULL)
	{
		printf("Extracting a file requires specifying an image file with -i, a CNE file with -c, and a header file with -h\n");
		exit(EXIT_FAILURE);
	}

	/* Image file */
	if ((out = open(fw->image_file, O_WRONLY | O_CREAT)) == -1)
	{
		printf("Could not open %s for writing.\n");
		exit(EXIT_FAILURE);
	}
	write(out, fw->image, fw->image_size);
	close(out);

	/* Header file */
	if ((out = open(fw->header_file, O_WRONLY | O_CREAT)) == -1)
	{
		printf("Could not open %s for writing.\n");
		exit(EXIT_FAILURE);
	}
	write(out, fw->header, 116);
	close(out);

	/* CNE file */
	if ((out = open(fw->cne_file, O_WRONLY | O_CREAT)) == -1)
	{
		printf("Could not open %s for writing.\n");
		exit(EXIT_FAILURE);
	}
	write(out, fw->cne, fw->cne_size);
	close(out);

	printf("Successfully extracted firmware file.\n");

	return;
}

void parse_header_file(struct firmware *fw)
{
	int fd;
	char *buffer = NULL;

	if ((fw == NULL) || fw->header_file == NULL)
	{
		printf("Header file not specified, or is invalid.\n");
		exit(EXIT_FAILURE);
	}	

	/* Open file */
	if ((fd = open(fw->header_file, O_RDONLY)) == -1)
	{
		printf("Could not open file: %s\n", fw->header_file);
		exit(EXIT_FAILURE);
	}

	/* Assumed to work */
	if (read(fd, fw->ident, sizeof(fw->ident) - 1) < 4)
	{
		printf("File is too short to be a valid .bcd file <4 bytes\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(fw->ident,"bCoD"))
	{
		printf("File does not appear to be a valid .bcd file\n");
		exit(EXIT_FAILURE);
	}

	/* File *could* be mangled past here, but I don't care */  
	read(fd, (char *)&fw->flags, 4);

	read(fd, (char *)&fw->timestamp, sizeof(fw->timestamp)-1);

	fw->timestamp[sizeof(fw->timestamp)-1] = '\0';

	read(fd, (char *)&fw->soft_id,  4);
	read(fd, (char *)&fw->soft_min, 2);
	read(fd, (char *)&fw->soft_mid, 2);

	read(fd, (char *)&fw->hardcomp, 4);

	read(fd, (char *)&fw->unknown1, 4);
	read(fd, (char *)&fw->unknown2, 4);

	read(fd, (char *)&fw->header_crc, 4);

	read(fd, (char *)&fw->image_offset, 4);
	read(fd, (char *)&fw->image_load_offset, 4);

	read(fd, (char *)&fw->image_size, 4);
	read(fd, (char *)&fw->image_crc, 4);

	read(fd, (char *)&fw->nulls,16);
	read(fd, (char *)&fw->cne_offset, 4);
	read(fd, (char *)&fw->unknown4, 4);
	read(fd, (char *)&fw->cne_size, 4);
	read(fd, (char *)&fw->cne_crc, 4);

	if ((fw->header = malloc(fw->image_offset)) == NULL)
	{
		printf("Could not allocate memory to store header\n");
		exit(EXIT_FAILURE);
	}

	lseek(fd, 0, SEEK_SET);

	read(fd, fw->header, fw->image_offset);

	close(fd);

	return;
}

void parse_image_file(struct firmware *fw)
{
	int fd;
	struct stat sb;
	char *buffer = NULL;

	if ((fw == NULL) || fw->image_file == NULL)
	{
		printf("Header file not specified, or is invalid.\n");
		exit(EXIT_FAILURE);
	}	

	/* Get information on the file */
	if (stat(fw->image_file, &sb) == -1)
	{
		printf("Could not stat: %s\n",fw->image_file);
		exit(EXIT_FAILURE);
	}

	/* Open file */
	if ((fd = open(fw->image_file, O_RDONLY)) == -1)
	{
		printf("Could not open file: %s\n", fw->image_file);
		exit(EXIT_FAILURE);
	}

	/* Read all contents of file, set size, calculate CRC */
	if ((buffer = malloc(sb.st_size)) == NULL)
	{
		printf("Could not allocate memory for image, barfing\n");
		exit(EXIT_FAILURE);
	}

	fw->image_size = sb.st_size;

	read(fd, buffer, fw->image_size);

	fw->image = buffer;

  fw->image_crc = CalcCRC32((unsigned char*)fw->image,fw->image_size,0,0);

	close(fd);

	return;
}


void parse_cne_file(struct firmware *fw)
{
	int fd;
	struct stat sb;
	char *buffer = NULL;

	if ((fw == NULL) || fw->cne_file == NULL)
	{
		printf("Header file not specified, or is invalid.\n");
		exit(EXIT_FAILURE);
	}	

	/* Get information on the file */
	if (stat(fw->cne_file, &sb) == -1)
	{
		printf("Could not stat: %s\n",fw->cne_file);
		exit(EXIT_FAILURE);
	}

	/* Open file */
	if ((fd = open(fw->cne_file, O_RDONLY)) == -1)
	{
		printf("Could not open file: %s\n", fw->cne_file);
		exit(EXIT_FAILURE);
	}

	/* Read all contents of file, set size, calculate CRC */
	if ((buffer = malloc(sb.st_size)) == NULL)
	{
		printf("Could not allocate memory for cne, barfing\n");
		exit(EXIT_FAILURE);
	}

	fw->cne_size = sb.st_size;

	read(fd, buffer, fw->cne_size);

	fw->cne = buffer;

  fw->cne_crc   = CalcCRC32((unsigned char*)fw->cne,fw->cne_size,0,0);

	close(fd);

	return;

}

void join_firmware_file(struct firmware *fw, const char *filename)
{
	int out;
	unsigned int cne_offset;

	if ((fw == NULL) || fw->image == NULL || fw->header == NULL || fw->cne == NULL)
	{
		printf("Joining a file requires specifying an image file with -i, a CNE file with -c, and a header file with -h\n");
		exit(EXIT_FAILURE);
	}

	if (filename == NULL)
	{
		printf("Filename to save to not specified with -b\n");
		exit(EXIT_FAILURE);
	}

	if ((out = open(filename, O_WRONLY | O_CREAT)) == -1)
	{
		printf("Could not open %s for writing.\n");
		exit(EXIT_FAILURE);
	}

	/* Substitute new values */

	/* CnE CRC location */
	memcpy((char *)&fw->header[92],(char *)&fw->cne_crc, 4);

	/* CnE Size Location */
	memcpy((char *)&fw->header[88],(char *)&fw->cne_size, 4);

	/* CnE Offset */
	cne_offset = fw->image_offset + fw->image_size;

	memcpy((char *)&fw->header[80],(char *)&cne_offset, 4);

	/* Image CRC location */
	memcpy((char *)&fw->header[60],(char *)&fw->image_crc, 4);

	/* Image Size location */
	memcpy((char *)&fw->header[56],(char *)&fw->image_size, 4);

	/* Zero out the header CRC */
	fw->header[44] = fw->header[45] = fw->header[46] = fw->header[47] = 0;

	/* Calculate the new header CRC */
	fw->header_crc = CalcCRC32((unsigned char*)fw->header,96,0,0);

	/* Header CRC location */
  memcpy((char *)&fw->header[44],(char *)&fw->header_crc, 4);

	write(out, fw->header, 96);
	lseek(out, fw->image_offset, SEEK_SET);
	printf("Writing to image offset: %x\n",fw->image_offset);
	write(out, fw->image, fw->image_size);
	lseek(out, cne_offset, SEEK_SET);
	printf("Writing to CNE offset: %x\n",fw->cne_offset);
	write(out, fw->cne, fw->cne_size);

	close(out);
}


void print_firmware_info(const struct firmware *fw)
{
	printf("Firmware information\n");
	printf("--------------------\n");
	printf("Timestamp   : %s\n",fw->timestamp);
	printf("Version     : %d.%d.%d\n",fw->soft_id,fw->soft_mid, fw->soft_min);
	printf("Image Size  : %d\n",fw->image_size);
	printf("Image Offset: 0x%x\n",fw->image_offset);
	printf("Cne Size    : %d\n",fw->cne_size);
	printf("Cne Offset  : 0x%x\n",fw->cne_offset);

	printf("\n\nCRCs\n");
	printf("Header CRC  : 0x%x\n",fw->header_crc);
	printf("Image  CRC  : 0x%x\n",fw->image_crc);
	printf("CNE    CRC  : 0x%x\n",fw->cne_crc);


	printf("\n\nMisc Info\n");
	printf("Soft ID: %d.%d.%d\n", fw->soft_id, fw->soft_mid, fw->soft_min);
	printf("HardComp: %d\n", fw->hardcomp);

	printf("Unknown1: 0x%x (%d)\n", fw->unknown1, fw->unknown1);
	printf("Unknown2: 0x%x (%d)\n", fw->unknown2, fw->unknown2);

}

void check_checksums(const struct firmware *fw)
{
	printf("\n\nVerifying Checksums\n");
	printf("--------------------\n");

	if (fw->header_crc == fw->p_header_crc)
		printf("Header CRC matched.\n");
	else
		printf("Header CRC mismatch. (%x) should be (%x)\n",fw->header_crc,
				fw->p_header_crc);  

	if (fw->image_crc == fw->p_image_crc)
		printf("Image CRC matched.\n");
	else
		printf("Image CRC mismatch. (%x) should be (%x)\n",fw->image_crc,
				fw->p_image_crc);

	if (fw->cne_crc == fw->p_cne_crc)
		printf("CNE CRC matched.\n");
	else
		printf("CNE CRC mismatch. (%x) should be (%x)\n",fw->cne_crc,
				fw->p_cne_crc);


}

void print_help(void)
{
	printf("WML11b firmware tool                                \n");
	printf("-----------------------------------------            \n");
	printf("Full list of commandline parameters:               \n\n");
	printf("-f	- Fix CRCs                                       \n");
	printf("-j	- Join firmware file (use with -h, -i, and -c)   \n");
	printf("-e	- Extract firmware file (use with -h, -i, and -c)\n");
	printf("-b	- BCD file (used with all options)               \n");
	printf("-h	- Header file (used with -e and -j)              \n");
	printf("-i	- Image file  (used with -e and -j)              \n");
	printf("-c	- CNE file    (used with -e and -j)              \n");
	printf("-p	- Print BCD file info                          \n\n");
	printf("Example Usage                                     :\n\n");
	printf("  Extract image.bin cne.bin and header.bin:\n");
	printf("    ./wml11b -e -b firmware_file.bcd -h header.bin -i image.bin -c cne.bin\n");
	printf("  Parse bcd file and print info, check CRCs:\n");
	printf("    ./wml11b -p -b firmware_file.bcd\n");
	printf("  Create .bcd file from image.bin cne.bin and header.bin (CRCs will be fixed automatically):\n");
	printf("    ./wml11b -j -b out.bcd -h header.bin -i image.bin -c cne.bin\n");
	printf("  Just fix CRCs in BCD file:\n");
	printf("    ./wml11b -f -b firmware_file.bcd\n\n");

	return;
}

int main(int argc, char *argv[])
{
	struct firmware *fw;
	int a;
	unsigned char flags = FLAG_NONE;
	char *filename = NULL;

	if (argc == 1)
	{
		print_help();
		return EXIT_FAILURE;
	}

	if ((fw = malloc(sizeof(struct firmware))) == NULL)
	{
		printf("Could not allocate memory for the firmware struct\n");
		return EXIT_FAILURE;
	}

	fw->header_file = NULL;
	fw->image_file  = NULL;
	fw->cne_file    = NULL;
	fw->out_file    = NULL;
	fw->in_file     = NULL;

	a = 1;
	while (a < argc)
	{
		if (!strcmp(argv[a],"-f"))
		{
			flags |= FLAG_FIX;
			a++;
		}
		else if (!strcmp(argv[a],"-p"))
		{
			flags |= FLAG_PRINT;
			a++;
		}
		else if (!strcmp(argv[a],"-b"))
		{
			a++;
			if (a == argc)
			{
				printf("Error: No filename provided with -b\n\n");
				return EXIT_FAILURE;
			}

			if ((filename = malloc(strlen(argv[a]))) == NULL)
			{
				printf("Could not allocate memory barfing\n");
				return EXIT_FAILURE;
			}

			strcpy(filename,argv[a++]);
		} 
		else if (!strcmp(argv[a],"-c"))
		{
			a++;
			if (a == argc)
			{
				printf("Error: No filename provided with -c\n\n");
				return EXIT_FAILURE;
			}

			if ((fw->cne_file = malloc(strlen(argv[a]))) == NULL)
			{
				printf("Could not allocate memory barfing\n");
				return EXIT_FAILURE;
			}

			strcpy(fw->cne_file,argv[a++]);

			flags |= FLAG_CNE;
		} 
		else if (!strcmp(argv[a],"-h"))
		{
			a++;
			if (a == argc)
			{
				printf("Error: No filename provided with -h\n\n");
				return EXIT_FAILURE;
			}

			if ((fw->header_file = malloc(strlen(argv[a]))) == NULL)
			{
				printf("Could not allocate memory barfing\n");
				return EXIT_FAILURE;
			}

			strcpy(fw->header_file,argv[a++]);

			flags |= FLAG_HEADER;
		} 
		else if (!strcmp(argv[a],"-i"))
		{
			a++;
			if (a == argc)
			{
				printf("Error: No filename provided with -i\n\n");
				return EXIT_FAILURE;
			}

			if ((fw->image_file = malloc(strlen(argv[a]))) == NULL)
			{
				printf("Could not allocate memory barfing\n");
				return EXIT_FAILURE;
			}

			strcpy(fw->image_file,argv[a++]);

			flags |= FLAG_IMAGE;
		} 
		else if (!strcmp(argv[a],"-j"))
		{
			flags |= FLAG_JOIN;
			a++;
		} 
		else if (!strcmp(argv[a],"-e"))
		{
			a++;
			flags |= FLAG_EXTRACT;
		} 
		else
			a++;
	}

	if ((flags & FLAG_JOIN) == FLAG_JOIN || (flags & FLAG_EXTRACT) == FLAG_EXTRACT)
	{ 
		if ((flags & (FLAG_JOIN | FLAG_EXTRACT)) == (FLAG_JOIN | FLAG_EXTRACT))
		{
			printf("Make up your damn mind already, join or extract.\n\n");
			return EXIT_FAILURE;
		}

		if ((flags & (FLAG_HEADER | FLAG_IMAGE | FLAG_CNE)) != (FLAG_HEADER | FLAG_IMAGE | FLAG_CNE))
		{
			printf("-h, -i, and -c MUST be used when -e or -j is used.\n\n");
			return EXIT_FAILURE;
		}
	}

	if (filename == NULL)
	{
		printf("No filename specified with -b\n");
		return EXIT_FAILURE;
	}

	if ((flags & FLAG_PRINT) == FLAG_PRINT)
	{
		printf("Firmware info for %s\n",filename);
		parse_firmware_file(fw, filename);
		print_firmware_info(fw);
		check_checksums(fw);
	}

	if ((flags & FLAG_EXTRACT) == FLAG_EXTRACT)
	{
		parse_firmware_file(fw, filename);
		extract_firmware_file(fw);
	}

	if ((flags & FLAG_JOIN) == FLAG_JOIN)
	{
		parse_header_file(fw);
		parse_image_file(fw);
		parse_cne_file(fw);
		join_firmware_file(fw, filename);
		printf("Successfully wrote %s\n",filename);
	}

	return EXIT_SUCCESS;
}

