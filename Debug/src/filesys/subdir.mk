################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/filesys/directory.c \
../src/filesys/file.c \
../src/filesys/filesys.c \
../src/filesys/free-map.c \
../src/filesys/fsutil.c \
../src/filesys/inode.c 

OBJS += \
./src/filesys/directory.o \
./src/filesys/file.o \
./src/filesys/filesys.o \
./src/filesys/free-map.o \
./src/filesys/fsutil.o \
./src/filesys/inode.o 

C_DEPS += \
./src/filesys/directory.d \
./src/filesys/file.d \
./src/filesys/filesys.d \
./src/filesys/free-map.d \
./src/filesys/fsutil.d \
./src/filesys/inode.d 


# Each subdirectory must supply rules for building sources it contributes
src/filesys/%.o: ../src/filesys/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


