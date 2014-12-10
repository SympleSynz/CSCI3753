/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.
  Modifications by Erik Eakins with inclusion of aes-crypt.c and xattr-utils.c

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <sys/xattr.h>
#include <time.h>

#include "aes-crypt.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif


//Create a struct to hold the path I want to use to the mirror point
//This will allow multiple processes using fuse, to have access to the information
//Because we store the struct in private_data
typedef struct 
{
	char* rootDir;
	char* passPhrase;
	int myTime;
}pathStruct;

//Created a helper function to create the path we are using to our mirror point
//This will reduce the amount of code I have to implement in each function to change the path
static void efs_completePath(char fullPath[PATH_MAX], const char *path, char* x)
{
	if (*x == 'd')
	{
		pathStruct *fpath = (pathStruct*)(fuse_get_context()->private_data);
		strcpy(fullPath,fpath->rootDir);
		strncat(fullPath, path, PATH_MAX);
	}
	else
	{
		char encPath[PATH_MAX];
		unsigned int i;
		pathStruct *fpath = (pathStruct*)(fuse_get_context()->private_data);
		strcpy(fullPath,fpath->rootDir);
		strcpy(encPath, path);
		for (i = 1; i < strlen(encPath) - 1; ++i)
		{
			if (i % 2 == 0)
			{	
				encPath[i] = 'a' + fpath->myTime;
			}
			else if (i % 3 == 0)
			{
				encPath[i] = 'z' - fpath->myTime;
			}
		}
		strncat(fullPath, encPath, PATH_MAX);
	}	
}

static int efs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = lstat(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_access(const char *path, int mask)
{
	int res;
	char fullPath[PATH_MAX];
	
	efs_completePath(fullPath,path,"d");

	res = access(fullPath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = readlink(fullPath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int efs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	dp = opendir(fullPath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int efs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fullPath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fullPath, mode);
	else
		res = mknod(fullPath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_mkdir(const char *path, mode_t mode)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"e");

	res = mkdir(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_unlink(const char *path)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = unlink(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_rmdir(const char *path)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = rmdir(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_symlink(const char *from, const char *to)
{
	int res;
	char new_from[PATH_MAX];
	char new_to[PATH_MAX];

	efs_completePath(new_from,from,"d");
	efs_completePath(new_to,to,"d");

	res = symlink(new_from, new_to);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_rename(const char *from, const char *to)
{
	int res;
	char new_from[PATH_MAX];
	char new_to[PATH_MAX];

	efs_completePath(new_from,from,"d");
	efs_completePath(new_to,to,"d");

	res = symlink(new_from, new_to);
	res = rename(new_from, new_to);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_link(const char *from, const char *to)
{
	int res;
	char new_from[PATH_MAX];
	char new_to[PATH_MAX];

	efs_completePath(new_from,from,"d");
	efs_completePath(new_to,to,"d");

	res = symlink(new_from, new_to);
	res = link(new_from, new_to);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_chmod(const char *path, mode_t mode)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = chmod(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = lchown(fullPath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_truncate(const char *path, off_t size)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = truncate(fullPath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fullPath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = open(fullPath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int efs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{//DECRYPT
	//int fd;
	int res;
	FILE* F;
	FILE* mem;
	size_t memSize;
	char* text;
	(void) fi;
	char fullPath[PATH_MAX];
	char extendedAttr[8];
	ssize_t extendedAttrLength;
	int action = -1; //set default as pass through (don't do anything)

	efs_completePath(fullPath,path,"d"); //We need to have the complete path to the file in the mirror pt
	char * key_str = ((pathStruct*) (fuse_get_context()->private_data))->passPhrase; //This gives us the passPhrase from when we mounted the system
	
	F = fopen(fullPath, "r"); //We open the file for read only
	mem = open_memstream(&text, & memSize); //This is a way of creating a temp file that isn't visable to the user

	if((F == NULL) || (mem == NULL)) //If anything doesn't work, error
		return -errno; 

	extendedAttrLength = getxattr(fullPath, "user.pa5-encfs.encrypted",extendedAttr, 8); //Checking the extended attributes of the file.
	//The getxattr returns the ssize_t of the value of the extended attribute
	if(extendedAttrLength != -1 && !memcmp(extendedAttr, "true", 4)) //If the attribute fails or the memory comparison of the value to "true" is the same
		action = 0; //We know that we will need to decrypt

	if(!do_crypt(F, mem, action, key_str)) //If the crypto fails, print error.  Call do_crypt to decrypt the file content to the temp mem file
    {
		fprintf(stderr, "do_crypt failed\n");
    }

    fclose(F); //close the main file
    fflush(mem); //flush on the temp file (make sure the contents on flushed in order to read)
    fseek(mem, offset, SEEK_SET); //move the the pointer to the appropriate offset based of the beginning of the file

	res = fread(buf, 1, size, mem); //read out the file from temp file
	if (res == -1)
		res = -errno;

	fclose(mem); //close temp file
	return res;
}

static int efs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{//ENCRYPT
	//int fd;
	int res;
	FILE* F;
	FILE* mem;
	size_t memSize;
	char* text;
	(void) fi;
	char fullPath[PATH_MAX];
	efs_completePath(fullPath,path,"d");
	char extendedAttr[8];
	ssize_t extendedAttrLength;
	char * key_str = ((pathStruct*) (fuse_get_context()->private_data))->passPhrase; //Must get the passPhrase to encrypt and decrypt
	int action = -1; //set default to pass through (don't do anything)

	F = fopen(fullPath, "r"); //Set real file to read only (in case we are appending the file)
	mem = open_memstream(&text,&memSize); //Open our temp file

	if((F == NULL) || (mem == NULL)) //Either fail, return error
		return -errno;

	extendedAttrLength = getxattr(fullPath, "user.pa5-encfs.encrypted",extendedAttr, 8); //Check the extended attributes to see if it is already encrypted
	if(extendedAttrLength != -1 && !memcmp(extendedAttr, "true", 4)) //if the returned ssize_t is not -1 (doesn't exist) and the value is "true", we must decrypt first
		action = 0;

	if(!do_crypt(F, mem, action, key_str)) //We are taking from the real file and decrypting the contents into the temp file
    {
		fprintf(stderr, "do_crypt failed\n");
    }
    //We do this because if we have to append a file, we are taking the full contents of the original file and adding to the end of it, our appending
    fclose(F);

    fflush(mem); //flush all of the temp file data
    fseek(mem, offset, SEEK_SET); //Move the file pointer to the offset in relation to the beginning of the file

    res = fwrite(buf,1, size, mem); //Now, we write to the temp file, with data from the buffer, which adds it to the bottom of the temp file's original data
    if (res == -1)
    	res = -errno;

    fflush(mem); //flush the temp data again

    F = fopen(fullPath, "w"); //Now we open the original file for writing
    fseek(mem, 0, SEEK_SET); //we need to move the file pointer back into the correct position to write from temp to real

    if (action == 0) //If we originally had to decrypt, then we must encrypt the file content
    	action = 1;

    if (!do_crypt(mem, F, action, key_str)) //Now we encrypt everything in the temp file into the real file
    {
    	fprintf(stderr, "do_crypt failed\n");
    }

    fclose(mem); //close temp file
    fclose(F); //close real file
	//close(fd);
	return res;
}

static int efs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");

	res = statvfs(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int efs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	(void) mode;
    (void) fi;
    FILE* F;
	FILE* mem;
	size_t memSize;
	char* text;
    char fullPath[PATH_MAX];

	char * key_str = ((pathStruct*) (fuse_get_context()->private_data))->passPhrase;

	efs_completePath(fullPath,path,"e");
	

	F = fopen(fullPath, "w"); //create a new file for writing
	mem = open_memstream(&text, &memSize); //open our temp file in case data must be written into the new file
	if (F == NULL) //if the file open fails, return error
		return -errno;

	if (!do_crypt(mem, F, 1, key_str)) //Encrypt everything from the temp file to the real file
    {
    	fprintf(stderr, "do_crypt failed\n");
    }

    if (setxattr(fullPath, "user.pa5-encfs.encrypted", "true", 4, 0)) //Now we must set the attribute of the new file
    	//we name the attribute "user.pa5-encfs.encrypted" and set its value to "true" with size 4 for value.
    	//Now, whenever we look for that specific attribute on a file, it'll have the "true" value associated to it
    	return -errno;

    fclose(mem); //close temp file
    fclose(F); //close real file

    return 0;
}


static int efs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int efs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int efs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	int res = lsetxattr(fullPath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int efs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	int res = lgetxattr(fullPath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int efs_listxattr(const char *path, char *list, size_t size)
{
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	int res = llistxattr(fullPath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int efs_removexattr(const char *path, const char *name)
{
	char fullPath[PATH_MAX];

	efs_completePath(fullPath,path,"d");
	int res = lremovexattr(fullPath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations efs_oper = {
	.getattr	= efs_getattr,
	.access		= efs_access,
	.readlink	= efs_readlink,
	.readdir	= efs_readdir,
	.mknod		= efs_mknod,
	.mkdir		= efs_mkdir, //Extra Credit, Encrypt file name
	.symlink	= efs_symlink,
	.unlink		= efs_unlink,
	.rmdir		= efs_rmdir,
	.rename		= efs_rename, //Extra Credit, Encrypt file name
	.link		= efs_link,
	.chmod		= efs_chmod,
	.chown		= efs_chown,
	.truncate	= efs_truncate,
	.utimens	= efs_utimens,
	.open		= efs_open,
	.read		= efs_read, //check attribute, decrypt content
	.write		= efs_write, //check attribute, encrypt content
	.statfs		= efs_statfs,
	.create     = efs_create,
	.release	= efs_release,
	.fsync		= efs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= efs_setxattr,
	.getxattr	= efs_getxattr,
	.listxattr	= efs_listxattr,
	.removexattr	= efs_removexattr,
#endif
};

int main(int argc, char *argv[])
{ 
	umask(0);
	//Throw an error if not enough arguments passed in
	if (argc < 4)
	{
		fprintf(stderr, "usage: %s %s\n", argv[0], "Missing: <Pass Phrase> <Mirror Directory> <Mount Point>");
		return 1;
	}
	pathStruct npath;  //Create a struct object
	npath.rootDir = realpath(argv[2], NULL); //Store the absolute path of the mirror point passed in.  realpath returns the absolute path if it exists, Null if it doesn't
	npath.passPhrase = argv[1]; //Store the password phrase to be used for encryption or decryption
	npath.myTime = (time(NULL)%10);
	return fuse_main(argc-2, argv+2, &efs_oper,(void*) &npath); //reduce argc by 2, for passphrase and mirror point.  Move the array pointer to the mount point
}
