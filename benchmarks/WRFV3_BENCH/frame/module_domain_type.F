MODULE module_domain_type

   USE module_driver_constants
   USE module_utility

   CHARACTER (LEN=80) program_name

   !  An entire domain.  This contains multiple meteorological fields by having
   !  arrays (such as "data_3d") of pointers for each field.  Also inside each
   !  domain is a link to a couple of other domains, one is just the 
   !  "next" domain that is to be stored, the other is the next domain which 
   !  happens to also be on the "same_level".

   TYPE domain_ptr
      TYPE(domain), POINTER :: ptr
   END TYPE domain_ptr

   INTEGER, PARAMETER :: HISTORY_ALARM=1, AUXHIST1_ALARM=2, AUXHIST2_ALARM=3,     &
                         AUXHIST3_ALARM=4, AUXHIST4_ALARM=5, AUXHIST5_ALARM=6,    &
                         AUXHIST6_ALARM=7, AUXHIST7_ALARM=8, AUXHIST8_ALARM=9,    &
                         AUXHIST9_ALARM=10, AUXHIST10_ALARM=11, AUXHIST11_ALARM=12,    &
                         AUXINPUT1_ALARM=13, AUXINPUT2_ALARM=14, AUXINPUT3_ALARM=15, &
                         AUXINPUT4_ALARM=16, AUXINPUT5_ALARM=17,                  &
                         AUXINPUT6_ALARM=18, AUXINPUT7_ALARM=19, AUXINPUT8_ALARM=20, &
                         AUXINPUT9_ALARM=21, AUXINPUT10_ALARM=22, AUXINPUT11_ALARM=23, &
                         RESTART_ALARM=24, BOUNDARY_ALARM=25, INPUTOUT_ALARM=26,  &  ! for outputing input (e.g. for 3dvar)
                         ALARM_SUBTIME=27,                                        &
                         COMPUTE_VORTEX_CENTER_ALARM=28,                          &
                         MAX_WRF_ALARMS=28  ! WARNING:  MAX_WRF_ALARMS must be 
                                            ! large enough to include all of 
                                            ! the alarms declared above.  

#include <state_subtypes.inc>

   TYPE domain

! SEE THE INCLUDE FILE FOR DEFINITIONS OF STATE FIELDS WITHIN THE DOMAIN DATA STRUCTURE
#include <state_struct.inc>

      INTEGER                                             :: comms( max_comms ), shift_x, shift_y

      INTEGER                                             :: id
      INTEGER                                             :: domdesc
      INTEGER                                             :: communicator
      INTEGER                                             :: iocommunicator
      INTEGER,POINTER                                     :: mapping(:,:)
      INTEGER,POINTER                                     :: i_start(:),i_end(:)
      INTEGER,POINTER                                     :: j_start(:),j_end(:)
      INTEGER                                             :: max_tiles
      INTEGER                                             :: num_tiles        ! taken out of namelist 20000908
      INTEGER                                             :: num_tiles_x      ! taken out of namelist 20000908
      INTEGER                                             :: num_tiles_y      ! taken out of namelist 20000908
      INTEGER                                             :: num_tiles_spec   ! place to store number of tiles computed from 
                                                                              ! externally specified params

      TYPE(domain_ptr) , DIMENSION( : ) , POINTER         :: parents                            
      TYPE(domain_ptr) , DIMENSION( : ) , POINTER         :: nests                            
      TYPE(domain) , POINTER                              :: sibling ! overlapped domains at same lev
      TYPE(domain) , POINTER                              :: intermediate_grid
      INTEGER                                             :: num_parents, num_nests, num_siblings
      INTEGER      , DIMENSION( max_parents )             :: child_of_parent
      INTEGER      , DIMENSION( max_nests )               :: active

      INTEGER      , DIMENSION(0:5)                       :: nframes          ! frames per outfile for history 
                                                                              ! streams (0 is main history)                  

      TYPE(domain) , POINTER                              :: next
      TYPE(domain) , POINTER                              :: same_level

      LOGICAL      , DIMENSION ( 4 )                      :: bdy_mask         ! which boundaries are on processor

      LOGICAL                                             :: first_force

      ! domain dimensions

      INTEGER    :: sd31,   ed31,   sd32,   ed32,   sd33,   ed33,         &
                    sd21,   ed21,   sd22,   ed22,                         &
                    sd11,   ed11

      INTEGER    :: sp31,   ep31,   sp32,   ep32,   sp33,   ep33,         &
                    sp21,   ep21,   sp22,   ep22,                         &
                    sp11,   ep11,                                         &
                    sm31,   em31,   sm32,   em32,   sm33,   em33,         &
                    sm21,   em21,   sm22,   em22,                         &
                    sm11,   em11,                                         &
                    sp31x,  ep31x,  sp32x,  ep32x,  sp33x,  ep33x,        &
                    sp21x,  ep21x,  sp22x,  ep22x,                        &
                    sm31x,  em31x,  sm32x,  em32x,  sm33x,  em33x,        &
                    sm21x,  em21x,  sm22x,  em22x,                        &
                    sp31y,  ep31y,  sp32y,  ep32y,  sp33y,  ep33y,        &
                    sp21y,  ep21y,  sp22y,  ep22y,                        &
                    sm31y,  em31y,  sm32y,  em32y,  sm33y,  em33y,        &
                    sm21y,  em21y,  sm22y,  em22y
      Type(WRFU_Clock), POINTER                           :: domain_clock
      Type(WRFU_Time)                                     :: start_subtime, stop_subtime
      Type(WRFU_Time)                                     :: this_bdy_time, next_bdy_time
      Type(WRFU_Time)                                     :: this_emi_time, next_emi_time
      Type(WRFU_TimeInterval), DIMENSION(MAX_WRF_ALARMS)  :: io_intervals
      Type(WRFU_Alarm), POINTER :: alarms(:)
! This awful hackery accounts for the fact that ESMF2.2.0 objects cannot tell 
! us if they have ever been created or not.  So, we have to keep track of this 
! ourselves to avoid destroying an object that has never been created!  Rip 
! this out once ESMF has useful introspection for creation...  
      LOGICAL :: domain_clock_created
      LOGICAL, POINTER :: alarms_created(:)

      ! Have clocks and times been initialized yet?
      LOGICAL :: time_set
!
! The following are used by the adaptive time step
! T. Hutchinson, WSI  1/11/07
!
      REAL :: max_cfl_val
      REAL :: last_max_vert_cfl
      REAL :: max_vert_cfl
      REAL :: max_horiz_cfl
      Type(WRFU_TimeInterval) :: last_dtInterval

      ! Time series location information
      INTEGER :: ntsloc, ntsloc_domain
      INTEGER :: next_ts_time
      INTEGER, POINTER, DIMENSION(:) :: itsloc, jtsloc, id_tsloc
      REAL, POINTER, DIMENSION(:) :: lattsloc, lontsloc
      CHARACTER (LEN=5), POINTER, DIMENSION(:) :: nametsloc
      CHARACTER (LEN=25), POINTER, DIMENSION(:) :: desctsloc
      CHARACTER (LEN=256), POINTER, DIMENSION(:) :: ts_filename
      LOGICAL :: have_calculated_tslocs

   END TYPE domain
END MODULE module_domain_type
