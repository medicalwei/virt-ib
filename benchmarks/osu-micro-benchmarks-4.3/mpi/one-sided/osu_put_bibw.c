#define BENCHMARK "OSU MPI_Put Bi-directional Bandwidth Test"
/*
 * Copyright (C) 2003-2014 the Network-Based Computing Laboratory
 * (NBCL), The Ohio State University.            
 *
 * Contact: Dr. D. K. Panda (panda@cse.ohio-state.edu)
 *
 * For detailed copyright and licensing information, please refer to the
 * copyright file COPYRIGHT in the top level OMB directory.
 */

#include <mpi.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>

#define MAX_ALIGNMENT 65536
#define MAX_SIZE (1<<22)

#define SKIP_LARGE  10
#define LOOP_LARGE  30
#define WINDOW_SIZE_LARGE 32
#define LARGE_MESSAGE_SIZE 8192

#define MYBUFSIZE ((MAX_SIZE * WINDOW_SIZE_LARGE) + MAX_ALIGNMENT)

#ifdef PACKAGE_VERSION
#   define HEADER "# " BENCHMARK " v" PACKAGE_VERSION "\n"
#else
#   define HEADER "# " BENCHMARK "\n"
#endif

#ifndef FIELD_WIDTH
#   define FIELD_WIDTH 20
#endif

#ifndef FLOAT_PRECISION
#   define FLOAT_PRECISION 2
#endif

#define MPI_CHECK(stmt)                                          \
do {                                                             \
   int mpi_errno = (stmt);                                       \
   if (MPI_SUCCESS != mpi_errno) {                               \
       fprintf(stderr, "[%s:%d] MPI call failed with %d \n",     \
        __FILE__, __LINE__,mpi_errno);                           \
       exit(EXIT_FAILURE);                                       \
   }                                                             \
   assert(MPI_SUCCESS == mpi_errno);                             \
} while (0)

int     skip = 20;
int     loop = 100;
double  t_start = 0.0, t_end = 0.0;
char    sbuf_original[MYBUFSIZE];
char    rbuf_original[MYBUFSIZE];
char    *sbuf=NULL, *rbuf=NULL;
MPI_Aint rdisp_remote;
MPI_Aint rdisp_local;

/* Window creation */
typedef enum {
    WIN_CREATE=0,
#if MPI_VERSION >= 3
    WIN_DYNAMIC,
    WIN_ALLOCATE,
#endif
} WINDOW;

/* Synchronization */
typedef enum {
    PSCW=0,
    FENCE,
} SYNC;

/*Header printout*/
char *win_info[20] = {
    "MPI_Win_create",
#if MPI_VERSION >= 3
    "MPI_Win_create_dynamic",
    "MPI_Win_allocate",
#endif
};

char *sync_info[20] = {
    "MPI_Win_post/start/complete/wait",
    "MPI_Win_fence",
};

enum po_ret_type {
    po_bad_usage,
    po_help_message,
    po_okay,
};

void print_header (int, WINDOW, SYNC); 
void print_bibw (int, int, double);
void print_help_message (int);
int  process_options (int, char **, WINDOW*, SYNC*, int);
void run_put_with_fence (int, WINDOW);
void run_put_with_pscw (int, WINDOW);
void allocate_memory (int, char *, int, WINDOW, MPI_Win *win);

int main (int argc, char *argv[])
{
    SYNC        sync_type=PSCW; 
    int         rank,nprocs;
    int         page_size;
    int         po_ret = po_okay;
#if MPI_VERSION >= 3
    WINDOW      win_type=WIN_ALLOCATE;
#else
    WINDOW      win_type=WIN_CREATE;
#endif

    MPI_CHECK(MPI_Init(&argc, &argv));
    MPI_CHECK(MPI_Comm_size(MPI_COMM_WORLD, &nprocs));
    MPI_CHECK(MPI_Comm_rank(MPI_COMM_WORLD, &rank));

    if(nprocs != 2) {
        if(rank == 0) {
            fprintf(stderr, "This test requires exactly two processes\n");
        }

        MPI_CHECK(MPI_Finalize());

        return EXIT_FAILURE;
    }

    po_ret = process_options(argc, argv, &win_type, &sync_type, rank);
    switch (po_ret) {
        case po_bad_usage:
            print_help_message(rank);
            MPI_CHECK(MPI_Finalize());
            return EXIT_FAILURE;
        case po_help_message:
            print_help_message(rank);
            MPI_CHECK(MPI_Finalize());
            return EXIT_SUCCESS;
    }

    page_size = getpagesize();
    assert(page_size <= MAX_ALIGNMENT);
    sbuf =
        (char *) (((unsigned long) sbuf_original + (page_size - 1)) /
                page_size * page_size);
    memset(sbuf, 0, MAX_SIZE);

    rbuf =
        (char *) (((unsigned long) rbuf_original + (page_size - 1)) /
                page_size * page_size);
    memset(rbuf, 0, MAX_SIZE);

    print_header(rank, win_type, sync_type);
    
    switch (sync_type){
        case FENCE: 
            run_put_with_fence(rank, win_type);
            break;
        default: 
            run_put_with_pscw(rank, win_type);
            break;
    }

    MPI_CHECK(MPI_Finalize());

    return EXIT_SUCCESS;
}

void print_help_message (int rank)
{
    if (rank) return;

#if MPI_VERSION >= 3
    printf("Usage: ./osu_put_bibw -w <win_option>  -s < sync_option> \n");
    printf("win_option:\n");
    printf("  create            use MPI_Win_create to create an MPI Window object\n");
    printf("  allocate          use MPI_Win_allocate to create an MPI Window object\n");
    printf("  dynamic           use MPI_Win_create_dynamic to create an MPI Window object\n");
    printf("\n");
#else
    printf("Usage: ./osu_put_bibw -s < sync_option> \n");
#endif

    printf("sync_option:\n");
    printf("  pscw              use Post/Start/Complete/Wait synchronization calls \n");
    printf("  fence             use MPI_Win_fence synchronization call\n");
    printf("\n");

    fflush(stdout);
}

int process_options(int argc, char *argv[], WINDOW *win, SYNC *sync, int rank)
{
    extern char *optarg;
    extern int  optind;
    extern int opterr;
    int c;

#if MPI_VERSION >= 3
    char const * optstring = "+w:s:h";
#else
    char const * optstring = "+s:h";
#endif

    if (rank) {
        opterr = 0;
    }

    while((c = getopt(argc, argv, optstring)) != -1) {
        switch (c) {
#if MPI_VERSION >= 3
            case 'w':
                if (0 == strcasecmp(optarg, "create")) {
                    *win = WIN_CREATE;
                }
                else if (0 == strcasecmp(optarg, "allocate")) {
                    *win = WIN_ALLOCATE;
                }
                else if (0 == strcasecmp(optarg, "dynamic")) {
                    *win = WIN_DYNAMIC;
                }
                else {
                    return po_bad_usage;
                }
                break;
#endif
            case 's':
                if (0 == strcasecmp(optarg, "pscw")) {
                    *sync = PSCW;
                }
                else if (0 == strcasecmp(optarg, "fence")) {
                    *sync = FENCE;
                }
                else {
                    return po_bad_usage;
                }
                break;
            case 'h':
                return po_help_message;
            default:
                return po_bad_usage;
        }
    }
    return po_okay;
}

void allocate_memory(int rank, char *rbuf, int size, WINDOW type, MPI_Win *win)
{
#if MPI_VERSION >= 3
    MPI_Status  reqstat;

    switch (type){
        case WIN_CREATE:
            MPI_CHECK(MPI_Win_create(rbuf, WINDOW_SIZE_LARGE*size, 1, MPI_INFO_NULL, MPI_COMM_WORLD, win));
            break;
        case WIN_DYNAMIC:
            MPI_CHECK(MPI_Win_create_dynamic(MPI_INFO_NULL, MPI_COMM_WORLD, win));
            MPI_CHECK(MPI_Win_attach(*win, rbuf, WINDOW_SIZE_LARGE*size));
            MPI_CHECK(MPI_Get_address(rbuf, &rdisp_local));
            if(rank == 0){
                MPI_CHECK(MPI_Send(&rdisp_local, 1, MPI_AINT, 1, 1, MPI_COMM_WORLD));
                MPI_CHECK(MPI_Recv(&rdisp_remote, 1, MPI_AINT, 1, 1, MPI_COMM_WORLD, &reqstat));
            }
            else{
                MPI_CHECK(MPI_Recv(&rdisp_remote, 1, MPI_AINT, 0, 1, MPI_COMM_WORLD, &reqstat));
                MPI_CHECK(MPI_Send(&rdisp_local, 1, MPI_AINT, 0, 1, MPI_COMM_WORLD));
            }
            break;
        default:
            MPI_CHECK(MPI_Win_allocate(WINDOW_SIZE_LARGE*size, 1, MPI_INFO_NULL, MPI_COMM_WORLD, rbuf, win));
            break;
    }
#else
    MPI_CHECK(MPI_Win_create(rbuf, WINDOW_SIZE_LARGE*size, 1, MPI_INFO_NULL, MPI_COMM_WORLD, win));
#endif
}

void print_header (int rank, WINDOW win, SYNC sync)
{
    if(rank == 0) {
        fprintf(stdout, HEADER);
        fprintf(stdout, "# Window creation: %s\n",
                win_info[win]);
        fprintf(stdout, "# Synchronization: %s\n",
                sync_info[sync]);
        fprintf(stdout, "%-*s%*s\n", 10, "# Size", FIELD_WIDTH, "Bandwidth (MB/s)");
        fflush(stdout);
    }
}

void print_bibw(int rank, int size, double t)
{
    if (rank == 0) {
        double tmp = size / 1e6 * loop * WINDOW_SIZE_LARGE;

        fprintf(stdout, "%-*d%*.*f\n", 10, size, FIELD_WIDTH,
                FLOAT_PRECISION, (tmp / t) * 2);
        fflush(stdout);
    }
}

/*Run PUT with Fence */
void run_put_with_fence(int rank, WINDOW type)
{
    double t; 
    int size, i, j;
    MPI_Aint disp = 0;
    MPI_Win     win;

    int window_size = WINDOW_SIZE_LARGE;

    for (size = 1; size <= MAX_SIZE; size = (size ? size * 2 : size + 1)) {
        allocate_memory(rank, rbuf, size, type, &win);

#if MPI_VERSION >= 3
        if (type == WIN_DYNAMIC) {
            disp = rdisp_remote;
        }
#endif

        if(size > LARGE_MESSAGE_SIZE) {
            loop = LOOP_LARGE;
            skip = SKIP_LARGE;
        }

        MPI_CHECK(MPI_Barrier(MPI_COMM_WORLD));

        if(rank == 0) {
            for (i = 0; i < skip + loop; i++) {
                if (i == skip) {
                    t_start = MPI_Wtime ();
                }
                MPI_CHECK(MPI_Win_fence(0, win));
                for(j = 0; j < window_size; j++) {
                    MPI_CHECK(MPI_Put(sbuf+(j*size), size, MPI_CHAR, 1, disp + (j * size), size, MPI_CHAR,
                            win));
                }
                MPI_CHECK(MPI_Win_fence(0, win));
                MPI_CHECK(MPI_Win_fence(0, win));
            }
            t_end = MPI_Wtime ();
            t = t_end - t_start;
        } else {
            for (i = 0; i < skip + loop; i++) {
                MPI_CHECK(MPI_Win_fence(0, win));
                MPI_CHECK(MPI_Win_fence(0, win));
                for(j = 0; j < window_size; j++) {
                    MPI_CHECK(MPI_Put(sbuf+(j*size), size, MPI_CHAR, 0, disp + (j * size), size, MPI_CHAR,
                            win));
                }
                MPI_CHECK(MPI_Win_fence(0, win));
            }
        }

        MPI_CHECK(MPI_Barrier(MPI_COMM_WORLD));

        print_bibw(rank, size, t);

        MPI_Win_free(&win);
    }
}

/*Run PUT with Post/Start/Complete/Wait */
void run_put_with_pscw(int rank, WINDOW type)
{
    double t; 
    int destrank, size, i, j;
    MPI_Aint disp = 0;
    MPI_Win     win;
    MPI_Group       comm_group, group;

    MPI_CHECK(MPI_Comm_group(MPI_COMM_WORLD, &comm_group));

    int window_size = WINDOW_SIZE_LARGE;
    for (size = 1; size <= MAX_SIZE; size = (size ? size * 2 : 1)) {
        allocate_memory(rank, rbuf, size, type, &win);

#if MPI_VERSION >= 3
        if (type == WIN_DYNAMIC) {
            disp = rdisp_remote;
        }
#endif

        if (size > LARGE_MESSAGE_SIZE) {
            loop = LOOP_LARGE;
            skip = SKIP_LARGE;
        }

        MPI_CHECK(MPI_Barrier(MPI_COMM_WORLD));

        if (rank == 0) {
            destrank = 1;
            MPI_CHECK(MPI_Group_incl (comm_group, 1, &destrank, &group));

            for (i = 0; i < skip + loop; i++) {

                if (i == skip) {
                    t_start = MPI_Wtime ();
                }

                MPI_CHECK(MPI_Win_post(group, 0, win));
                MPI_CHECK(MPI_Win_start(group, 0, win));

                for(j = 0; j < window_size; j++) {
                    MPI_CHECK(MPI_Put(sbuf + j*size, size, MPI_CHAR, 1, disp + (j*size), size, MPI_CHAR,
                            win));
                }

                MPI_CHECK(MPI_Win_complete(win));
                MPI_CHECK(MPI_Win_wait(win));
            }
            t_end = MPI_Wtime();
            t = t_end - t_start;
        } else {
            destrank = 0;
            MPI_CHECK(MPI_Group_incl(comm_group, 1, &destrank, &group));

            for (i = 0; i < skip + loop; i++) {
                MPI_CHECK(MPI_Win_post(group, 0, win));
                MPI_CHECK(MPI_Win_start(group, 0, win));

                for (j = 0; j < window_size; j++) {
                    MPI_CHECK(MPI_Put(sbuf + j*size, size, MPI_CHAR, 0, disp + (j*size), size, MPI_CHAR,
                            win));
                }

                MPI_CHECK(MPI_Win_complete(win));
                MPI_CHECK(MPI_Win_wait(win));
            }
        }

        MPI_CHECK(MPI_Barrier(MPI_COMM_WORLD));

        print_bibw(rank, size, t);

        MPI_CHECK(MPI_Group_free(&group));
        MPI_Win_free(&win);
    }
    MPI_CHECK(MPI_Group_free(&comm_group));
}
/* vi: set sw=4 sts=4 tw=80: */
