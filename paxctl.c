/*
 * PaX control
 * Copyright 2004,2005,2006,2007 PaX Team <pageexec@freemail.hu>
 * Licensed under the GNU GPL version 2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "paxctl.h"

static void report_flags(const Elf64_Word flags, const struct pax_state * const state)
{
  char buffer[13];

  /* the logic is: lower case: explicitly disabled, upper case: explicitly enabled, - : default */
  buffer[0] = (flags & PF_PAGEEXEC    ? 'P' : '-');
  buffer[1] = (flags & PF_NOPAGEEXEC  ? 'p' : '-');
  buffer[2] = (flags & PF_SEGMEXEC    ? 'S' : '-');
  buffer[3] = (flags & PF_NOSEGMEXEC  ? 's' : '-');
  buffer[4] = (flags & PF_MPROTECT    ? 'M' : '-');
  buffer[5] = (flags & PF_NOMPROTECT  ? 'm' : '-');
  buffer[6] = (flags & PF_RANDEXEC    ? 'X' : '-');
  buffer[7] = (flags & PF_NORANDEXEC  ? 'x' : '-');
  buffer[8] = (flags & PF_EMUTRAMP    ? 'E' : '-');
  buffer[9] = (flags & PF_NOEMUTRAMP  ? 'e' : '-');
  buffer[10] = (flags & PF_RANDMMAP   ? 'R' : '-');
  buffer[11] = (flags & PF_NORANDMMAP ? 'r' : '-');
  buffer[12] = 0;

  fprintf(stdout, "- PaX flags: %s [%s]\n", buffer, state->argv[state->files]);

  if (state->shortonly)
    return;

  if (flags & PF_PAGEEXEC)   fprintf(stdout, "\tPAGEEXEC is enabled\n");
  if (flags & PF_NOPAGEEXEC) fprintf(stdout, "\tPAGEEXEC is disabled\n");
  if (flags & PF_SEGMEXEC)   fprintf(stdout, "\tSEGMEXEC is enabled\n");
  if (flags & PF_NOSEGMEXEC) fprintf(stdout, "\tSEGMEXEC is disabled\n");
  if (flags & PF_MPROTECT)   fprintf(stdout, "\tMPROTECT is enabled\n");
  if (flags & PF_NOMPROTECT) fprintf(stdout, "\tMPROTECT is disabled\n");
  if (flags & PF_RANDEXEC)   fprintf(stdout, "\tRANDEXEC is enabled\n");
  if (flags & PF_NORANDEXEC) fprintf(stdout, "\tRANDEXEC is disabled\n");
  if (flags & PF_EMUTRAMP)   fprintf(stdout, "\tEMUTRAMP is enabled\n");
  if (flags & PF_NOEMUTRAMP) fprintf(stdout, "\tEMUTRAMP is disabled\n");
  if (flags & PF_RANDMMAP)   fprintf(stdout, "\tRANDMMAP is enabled\n");
  if (flags & PF_NORANDMMAP) fprintf(stdout, "\tRANDMMAP is disabled\n");
}

#define elf_modify_phdr(bit)														\
static int elf##bit##_modify_phdr(struct pax_state * const state)									\
{																	\
  unsigned int i, pt_phdr, pt_load, gnu_stack, pax_flags;										\
  Elf##bit##_Phdr * phdr = state->ops->phdr._##bit;											\
  Elf##bit##_Shdr * shdr = state->ops->shdr._##bit;											\
																	\
  /* init phdr info */															\
  pt_phdr = state->ops->phnum._##bit;													\
  pt_load = state->ops->phnum._##bit;													\
  gnu_stack = state->ops->phnum._##bit;													\
  pax_flags = state->ops->phnum._##bit;													\
																	\
  /* verify shdr info */														\
  for (i = 0U; i < state->ops->shnum._##bit; i++) {											\
    if (SHT_NULL == shdr[i].sh_type)													\
      continue;																\
																	\
    if ((shdr[i].sh_addralign && (~(shdr[i].sh_addralign - 1) + shdr[i].sh_addralign)) ||						\
        (shdr[i].sh_addralign && shdr[i].sh_addr && (shdr[i].sh_addr & (shdr[i].sh_addralign - 1))) ||					\
        (shdr[i].sh_addr && shdr[i].sh_addr + shdr[i].sh_size < shdr[i].sh_addr) ||							\
        shdr[i].sh_offset < sizeof(Elf##bit##_Ehdr) + sizeof(Elf##bit##_Phdr) * state->ops->phnum._##bit ||				\
        shdr[i].sh_offset + shdr[i].sh_size < shdr[i].sh_offset ||									\
        (SHT_NOBITS != shdr[i].sh_type && shdr[i].sh_offset + shdr[i].sh_size > state->size))						\
    {																	\
      if (!state->quiet)														\
        fprintf(stderr, "file %s is not a valid ELF executable (invalid SHT_ entry:%u)\n", state->argv[state->files], i);		\
      return EXIT_FAILURE;														\
    }																	\
  }																	\
																	\
  /* gather/verify phdr info */														\
  for (i = 0U; i < state->ops->phnum._##bit; i++) {											\
    if ((phdr[i].p_align && (~(phdr[i].p_align - 1) + phdr[i].p_align)) ||								\
        (phdr[i].p_align && ((phdr[i].p_offset ^ phdr[i].p_vaddr) & (phdr[i].p_align - 1))) ||						\
        phdr[i].p_vaddr + phdr[i].p_memsz < phdr[i].p_vaddr ||										\
        phdr[i].p_offset + phdr[i].p_filesz < phdr[i].p_offset ||									\
        phdr[i].p_offset + phdr[i].p_filesz > state->size ||										\
        phdr[i].p_filesz > phdr[i].p_memsz)												\
    {																	\
      if (!state->quiet)														\
        fprintf(stderr, "file %s is not a valid ELF executable (invalid PT_ entry:%u)\n", state->argv[state->files], i);		\
      return EXIT_FAILURE;														\
    }																	\
																	\
    switch (phdr[i].p_type) {														\
    case PT_PHDR:															\
      if (pt_phdr == state->ops->phnum._##bit) {											\
        if (pt_load != state->ops->phnum._##bit) {											\
          if (!state->quiet)														\
            fprintf(stderr, "file %s is not a valid ELF executable (PT_LOAD before PT_PHDR)\n", state->argv[state->files]);		\
          return EXIT_FAILURE;														\
        }																\
        pt_phdr = i;															\
      } else {																\
        if (!state->quiet)														\
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_PHDR)\n", state->argv[state->files]);		\
        return EXIT_FAILURE;														\
      }																	\
      break;																\
																	\
    case PT_LOAD:															\
      if (pt_load == state->ops->phnum._##bit)												\
        pt_load = i;															\
      break;																\
																	\
    case PT_PAX_FLAGS:															\
      if (pax_flags != state->ops->phnum._##bit) {											\
        if (!state->quiet)														\
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_PAX_FLAGS)\n", state->argv[state->files]);		\
        return EXIT_FAILURE;														\
      }																	\
      pax_flags = i;															\
      break;																\
																	\
    case PT_GNU_STACK:															\
      if (gnu_stack != state->ops->phnum._##bit) {											\
        if (!state->quiet)														\
          fprintf(stderr, "file %s is not a valid ELF executable (more than one PT_GNU_STACK)\n", state->argv[state->files]);		\
        return EXIT_FAILURE;														\
      }																	\
      gnu_stack = i;															\
      break;																\
    }																	\
  }																	\
																	\
  /* verify phdr info */														\
  if (pt_load == state->ops->phnum._##bit) {												\
    if (!state->quiet)															\
      fprintf(stderr, "file %s is not a valid ELF executable (no PT_LOAD found)\n", state->argv[state->files]);				\
    return EXIT_FAILURE;														\
  }																	\
																	\
  if (pt_phdr < state->ops->phnum._##bit) {												\
    if (phdr[pt_phdr].p_vaddr + phdr[pt_phdr].p_memsz <= phdr[pt_load].p_vaddr ||							\
        phdr[pt_load].p_vaddr + phdr[pt_load].p_memsz <= phdr[pt_phdr].p_vaddr) {							\
      if (!state->quiet)														\
        fprintf(stderr, "file %s is not a valid ELF executable (PT_PHDR is outside of first PT_LOAD)\n", state->argv[state->files]);	\
      return EXIT_FAILURE;														\
    }																	\
  }																	\
																	\
  /* convert PT_GNU_STACK if necessary/possible */											\
  if (pax_flags == state->ops->phnum._##bit && state->convert) {									\
    if (gnu_stack < state->ops->phnum._##bit) {												\
      pax_flags = gnu_stack;														\
      phdr[pax_flags].p_type = PT_PAX_FLAGS;												\
      phdr[pax_flags].p_flags = PF_NORANDEXEC | PF_NOEMUTRAMP;										\
      if (!state->quiet)														\
        fprintf(stderr, "file %s had a PT_GNU_STACK program header, converted\n", state->argv[state->files]);				\
    } else {																\
      if (!state->quiet)														\
        fprintf(stderr, "file %s does not have a PT_GNU_STACK program header, conversion failed\n", state->argv[state->files]);		\
    }																	\
  }																	\
																	\
  /* create PT_PAX_FLAGS if necessary/possible */											\
  if (pax_flags == state->ops->phnum._##bit && state->create) {										\
    Elf##bit##_Word shift = phdr[pt_load].p_align;											\
																	\
    if (shift == phdr[pt_load].p_vaddr) {												\
      shift >>= 1;															\
      if (!state->quiet)														\
        fprintf(stderr, "file %s will be realigned, beware\n", state->argv[state->files]);						\
    }																	\
																	\
    if ((pt_phdr == state->ops->phnum._##bit ||												\
        (phdr[pt_phdr].p_offset == sizeof(Elf##bit##_Ehdr) &&										\
         phdr[pt_phdr].p_align < shift &&												\
         phdr[pt_phdr].p_memsz + sizeof(Elf##bit##_Phdr) < phdr[pt_load].p_memsz)) &&							\
        phdr[pt_load].p_vaddr > shift &&												\
        state->size + shift > shift)													\
    {																	\
      unsigned char * newmap;														\
      Elf##bit##_Ehdr * ehdr;														\
      Elf##bit##_Phdr * newphdr;													\
																	\
      /* unmap old mapping with old size */												\
      if (-1 == munmap(state->map, state->size)) {											\
        if (!state->quiet)														\
          perror(state->argv[state->files]);												\
        return EXIT_FAILURE;														\
      }																	\
																	\
      /* set up new size */														\
      state->size += shift;														\
																	\
      /* adjust underlying file size */													\
      if (-1 == ftruncate(state->fd, (off_t)state->size)) {										\
        if (!state->quiet)														\
          perror(state->argv[state->files]);												\
        return EXIT_FAILURE;														\
      }																	\
																	\
      /* map underlying file again with the new size */											\
      newmap = mmap(NULL, state->size, PROT_READ | PROT_WRITE, MAP_SHARED, state->fd, (off_t)0);					\
      if (MAP_FAILED == newmap) {													\
        if (!state->quiet)														\
          perror(state->argv[state->files]);												\
        return EXIT_FAILURE;														\
      }																	\
																	\
      /* adjust pointers based on the new mapping */											\
      phdr = state->ops->phdr._##bit = (Elf##bit##_Phdr *)((unsigned char*)phdr + (newmap - state->map));				\
      if (shdr)																\
        shdr = state->ops->shdr._##bit = (Elf##bit##_Shdr *)((unsigned char*)shdr + (newmap - state->map));				\
      state->map = newmap;														\
																	\
      /* make room for the new PHDR */													\
      memmove(state->map + shift, state->map, state->size - shift);									\
      memset(state->map + sizeof(Elf##bit##_Ehdr), 0, shift - sizeof(Elf##bit##_Ehdr));							\
																	\
      /* adjust pointers again */													\
      phdr = state->ops->phdr._##bit = (Elf##bit##_Phdr *)((unsigned char*)phdr + shift);						\
      if (shdr)																\
        shdr = state->ops->shdr._##bit = (Elf##bit##_Shdr *)((unsigned char*)shdr + shift);						\
																	\
      /* adjust file offsets: ehdr */													\
      ehdr = (Elf##bit##_Ehdr *)state->map;												\
      if (shdr)																\
        ehdr->e_shoff += shift;														\
																	\
      /* adjust file offsets: phdr */													\
      newphdr = (Elf##bit##_Phdr *)(state->map + ehdr->e_phoff);									\
      for (i = 0; i < state->ops->phnum._##bit; i++) {											\
        newphdr[i] = phdr[i];														\
        if (newphdr[i].p_offset >= sizeof(Elf##bit##_Ehdr) + sizeof(Elf##bit##_Phdr) * state->ops->phnum._##bit)			\
          newphdr[i].p_offset += shift;													\
        else if (newphdr[i].p_vaddr >= phdr[pt_load].p_vaddr) {										\
          newphdr[i].p_vaddr -= shift;													\
          newphdr[i].p_paddr -= shift;													\
        }																\
        if (newphdr[i].p_align > shift)													\
          newphdr[i].p_align = shift;													\
      }																	\
      newphdr[pt_load].p_memsz += shift;												\
      newphdr[pt_load].p_filesz += shift;												\
																	\
      /* the moment of truth */														\
      pax_flags = i;															\
      newphdr[pax_flags].p_type = PT_PAX_FLAGS;												\
      newphdr[pax_flags].p_flags = PF_NORANDEXEC | PF_NOEMUTRAMP;									\
      newphdr[pax_flags].p_align = 4;													\
      if (pt_phdr < state->ops->phnum._##bit) {												\
        newphdr[pt_phdr].p_memsz += sizeof(Elf##bit##_Phdr);										\
        newphdr[pt_phdr].p_filesz += sizeof(Elf##bit##_Phdr);										\
      } else																\
        pt_phdr++;															\
      ehdr->e_phnum += 1;														\
      state->ops->phnum._##bit += 1;													\
      phdr = newphdr;															\
																	\
      /* adjust file offsets: shdr */													\
      for (i = 0; i < state->ops->shnum._##bit; i++) {											\
        if (shdr[i].sh_offset)														\
          shdr[i].sh_offset += shift;													\
      }																	\
																	\
      if (!state->quiet)														\
        fprintf(stderr, "file %s got a new PT_PAX_FLAGS program header\n", state->argv[state->files]);					\
    }																	\
    if (pax_flags == state->ops->phnum._##bit) {											\
      if (!state->quiet)														\
        fprintf(stderr, "file %s cannot have a PT_PAX_FLAGS program header, creation failed\n", state->argv[state->files]);		\
    }																	\
  }																	\
																	\
  if (pax_flags == state->ops->phnum._##bit) {												\
    if (!state->quiet && !state->convert && !state->create)										\
      fprintf(stderr, "file %s does not have a PT_PAX_FLAGS program header, try conversion\n", state->argv[state->files]);		\
    return EXIT_FAILURE;														\
  }																	\
																	\
  if (state->view)															\
    report_flags(phdr[pax_flags].p_flags, state);											\
  if (state->flags_on | state->flags_off) {												\
    const Elf##bit##_Ehdr * const ehdr = (const Elf##bit##_Ehdr *)state->map;								\
																	\
    if (ehdr->e_type == ET_DYN) {													\
      phdr[pax_flags].p_flags &= ~((state->flags_off | PF_RANDEXEC) & ~PF_NORANDEXEC);							\
      phdr[pax_flags].p_flags |= (state->flags_on | PF_NORANDEXEC) & ~PF_RANDEXEC;							\
    } else {																\
      phdr[pax_flags].p_flags &= ~state->flags_off;											\
      phdr[pax_flags].p_flags |= state->flags_on;											\
    }																	\
  }																	\
  return EXIT_SUCCESS;															\
}

elf_modify_phdr(32);
elf_modify_phdr(64);

static struct elf_ops elf32 = {
  .modify_phdr = elf32_modify_phdr,
};

static struct elf_ops elf64 = {
  .modify_phdr = elf64_modify_phdr,
};

static void banner(void)
{
  fprintf(stderr,
    "PaX control v" PAXCTL_VERSION "\n"
    "Copyright 2004,2005,2006,2007 PaX Team <pageexec@freemail.hu>\n\n");
}

static void usage(void)
{
  banner();
  fprintf(stderr,
    "usage: paxctl <options> <files>\n\n"
    "options:\n"
    "\t-p: disable PAGEEXEC\t\t-P: enable PAGEEXEC\n"
    "\t-e: disable EMUTRMAP\t\t-E: enable EMUTRMAP\n"
    "\t-m: disable MPROTECT\t\t-M: enable MPROTECT\n"
    "\t-r: disable RANDMMAP\t\t-R: enable RANDMMAP\n"
    "\t-x: disable RANDEXEC\t\t-X: enable RANDEXEC\n"
    "\t-s: disable SEGMEXEC\t\t-S: enable SEGMEXEC\n\n"
    "\t-v: view flags\t\t\t-z: restore default flags\n"
    "\t-q: suppress error messages\t-Q: report flags in short format\n"
    "\t-c: convert PT_GNU_STACK into PT_PAX_FLAGS (see manpage!)\n"
    "\t-C: create PT_PAX_FLAGS (see manpage!)\n"
  );
  exit(EXIT_FAILURE);
}

static int is_elf32(struct pax_state * const state)
{
  const Elf32_Ehdr * const ehdr = (const Elf32_Ehdr *)state->map;

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG))
    return 0;
  if (ehdr->e_ehsize != sizeof(Elf32_Ehdr))
    return 0;
  if ((ehdr->e_version != EV_CURRENT) || (ehdr->e_ident[EI_CLASS] != ELFCLASS32))
    return 0;
  if ((ehdr->e_type != ET_EXEC) && (ehdr->e_type != ET_DYN))
    return 0;

  if (!ehdr->e_phoff || !ehdr->e_phnum || sizeof(Elf32_Phdr) != ehdr->e_phentsize)
    return 0;
  if (ehdr->e_phnum > 65536U / ehdr->e_phentsize - 1)
    return 0;
  if (ehdr->e_phoff > ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)
    return 0;
  if ((Elf32_Off)state->size < ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)
    return 0;

  if (ehdr->e_shoff) {
    if (!ehdr->e_shnum || sizeof(Elf32_Shdr) != ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shnum > 65536U / ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shoff > ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
    if ((Elf32_Off)state->size < ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
  }

  state->ops = &elf32;
  state->ops->phdr._32 = (Elf32_Phdr *)(state->map + ehdr->e_phoff);
  state->ops->phnum._32 = ehdr->e_phnum;
  if (ehdr->e_shoff) {
    state->ops->shdr._32 = (Elf32_Shdr *)(state->map + ehdr->e_shoff);
    state->ops->shnum._32 = ehdr->e_shnum;
  } else {
    state->ops->shdr._32 = NULL;
    state->ops->shnum._32 = 0;
  }

  return 1;
}

static int is_elf64(struct pax_state * const state)
{
  const Elf64_Ehdr * const ehdr = (const Elf64_Ehdr *)state->map;

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG))
    return 0;
  if (ehdr->e_ehsize != sizeof(Elf64_Ehdr))
    return 0;
  if ((ehdr->e_version != EV_CURRENT) || (ehdr->e_ident[EI_CLASS] != ELFCLASS64))
    return 0;
  if ((ehdr->e_type != ET_EXEC) && (ehdr->e_type != ET_DYN))
    return 0;

  if (!ehdr->e_phoff || !ehdr->e_phnum || sizeof(Elf64_Phdr) != ehdr->e_phentsize)
    return 0;
  if (ehdr->e_phnum > 65536U / ehdr->e_phentsize - 1)
    return 0;
  if (ehdr->e_phoff > ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)
    return 0;
  if ((Elf64_Off)state->size < ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)
    return 0;

  if (ehdr->e_shoff) {
    if (!ehdr->e_shnum || sizeof(Elf64_Shdr) != ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shnum > 65536U / ehdr->e_shentsize)
      return 0;
    if (ehdr->e_shoff > ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
    if ((Elf64_Off)state->size < ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)
      return 0;
  }

  state->ops = &elf64;
  state->ops->phdr._64 = (Elf64_Phdr *)(state->map + ehdr->e_phoff);
  state->ops->phnum._64 = ehdr->e_phnum;
  if (ehdr->e_shoff) {
    state->ops->shdr._64 = (Elf64_Shdr *)(state->map + ehdr->e_shoff);
    state->ops->shnum._64 = ehdr->e_shnum;
  } else {
    state->ops->shdr._64 = NULL;
    state->ops->shnum._64 = 0;
  }

  return 1;
}

static int pax_verify_file(struct pax_state * const state)
{
  int fd, oflags, mflags;
  struct stat st;

  if (state->flags_on | state->flags_off | state->convert | state->create) {
    oflags = O_RDWR;
    mflags = PROT_READ | PROT_WRITE;
  } else {
    oflags = O_RDONLY;
    mflags = PROT_READ;
  }

  fd = open(state->argv[state->files], oflags);
  if (-1 == fd) {
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (-1 == fstat(fd, &st)) {
    close(fd);
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  state->size = st.st_size;
  state->map = mmap(NULL, state->size, mflags, MAP_SHARED, fd, (off_t)0);
  if (MAP_FAILED == state->map) {
    state->map = NULL;
    state->size = 0;
    close(fd);
    if (!state->quiet)
      perror(state->argv[state->files]);
    return EXIT_FAILURE;
  }

  if (state->size < sizeof(Elf64_Ehdr) || (!is_elf32(state) && !is_elf64(state))) {
    munmap(state->map, (size_t)st.st_size);
    state->map = NULL;
    state->size = 0;
    close(fd);
    if (!state->quiet)
      fprintf(stderr, "file %s is not a valid ELF executable\n", state->argv[state->files]);
    return EXIT_FAILURE;
  }

  state->fd = fd;

  return EXIT_SUCCESS;
}

static int pax_process_file(struct pax_state * const state)
{
  int ret = EXIT_FAILURE;

  /* get/verify ELF header */
  if (EXIT_SUCCESS == pax_verify_file(state)) {
    /* report/modify program header */
    ret = state->ops->modify_phdr(state);

    munmap(state->map, state->size);
    close(state->fd);
    state->map = NULL;
    state->size = 0;
    state->fd = -1;
  }

  return ret;
}

static int pax_process_files(struct pax_state * const state)
{
  int status = EXIT_SUCCESS;

  while (state->argv[state->files]) {
    if (EXIT_SUCCESS != pax_process_file(state))
        status = EXIT_FAILURE;
    ++state->files;
  }

  return status;
}

static int pax_parse_args(int argc, struct pax_state * const state)
{
  while (1) {
    switch(getopt(argc, state->argv, "pPsSmMeErRxXvqQzcC")) {
    case -1:
      state->files = optind;
      return optind < argc ? EXIT_SUCCESS : EXIT_FAILURE;

    case '?':
      return EXIT_FAILURE;

#define parse_flag(option1, option2, flag)	\
    case option1:				\
      state->flags_on &= ~PF_##flag;		\
      state->flags_on |= PF_NO##flag;		\
      state->flags_off &= ~PF_NO##flag;		\
      state->flags_off |= PF_##flag;		\
      break;					\
    case option2:				\
      state->flags_on &= ~PF_NO##flag;		\
      state->flags_on |= PF_##flag;		\
      state->flags_off &= ~PF_##flag;		\
      state->flags_off |= PF_NO##flag;		\
      break;

    parse_flag('p', 'P', PAGEEXEC);
    parse_flag('s', 'S', SEGMEXEC);
    parse_flag('m', 'M', MPROTECT);
    parse_flag('e', 'E', EMUTRAMP);
    parse_flag('r', 'R', RANDMMAP);
    parse_flag('x', 'X', RANDEXEC);

#undef parse_flag

    case 'v':
      state->view = 1;
      break;

    case 'q':
      state->quiet = 1;
      break;

    case 'Q':
      state->shortonly = 1;
      break;

    case 'z':
      state->flags_on = 0U;
      state->flags_off = PF_PAX_MASK;
      break;

    case 'c':
      state->convert = 1;
      break;

    case 'C':
      state->create = 1;
      break;
    }
  }
}

int main(int argc, char * argv[])
{
  struct pax_state state = {
    .argv = argv,
    .flags_on = 0U,
    .flags_off = 0U,
    .files = 0U,
    .quiet = 0,
    .shortonly = 0,
    .view = 0,
    .convert = 0,
    .create = 0,
    .ops = NULL,
    .map = NULL,
    .size = 0,
    .fd = -1,
  };

  if (3 > argc)
    usage();

  /* parse arguments */
  if (EXIT_SUCCESS != pax_parse_args(argc, &state))
    return EXIT_FAILURE;

  if (state.view)
    banner();

  /* process files */
  return pax_process_files(&state);
}
