################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/filesys/base/child-syn-read.c \
../src/tests/filesys/base/child-syn-wrt.c \
../src/tests/filesys/base/lg-create.c \
../src/tests/filesys/base/lg-full.c \
../src/tests/filesys/base/lg-random.c \
../src/tests/filesys/base/lg-seq-block.c \
../src/tests/filesys/base/lg-seq-random.c \
../src/tests/filesys/base/sm-create.c \
../src/tests/filesys/base/sm-full.c \
../src/tests/filesys/base/sm-random.c \
../src/tests/filesys/base/sm-seq-block.c \
../src/tests/filesys/base/sm-seq-random.c \
../src/tests/filesys/base/syn-read.c \
../src/tests/filesys/base/syn-remove.c \
../src/tests/filesys/base/syn-write.c 

OBJS += \
./src/tests/filesys/base/child-syn-read.o \
./src/tests/filesys/base/child-syn-wrt.o \
./src/tests/filesys/base/lg-create.o \
./src/tests/filesys/base/lg-full.o \
./src/tests/filesys/base/lg-random.o \
./src/tests/filesys/base/lg-seq-block.o \
./src/tests/filesys/base/lg-seq-random.o \
./src/tests/filesys/base/sm-create.o \
./src/tests/filesys/base/sm-full.o \
./src/tests/filesys/base/sm-random.o \
./src/tests/filesys/base/sm-seq-block.o \
./src/tests/filesys/base/sm-seq-random.o \
./src/tests/filesys/base/syn-read.o \
./src/tests/filesys/base/syn-remove.o \
./src/tests/filesys/base/syn-write.o 

C_DEPS += \
./src/tests/filesys/base/child-syn-read.d \
./src/tests/filesys/base/child-syn-wrt.d \
./src/tests/filesys/base/lg-create.d \
./src/tests/filesys/base/lg-full.d \
./src/tests/filesys/base/lg-random.d \
./src/tests/filesys/base/lg-seq-block.d \
./src/tests/filesys/base/lg-seq-random.d \
./src/tests/filesys/base/sm-create.d \
./src/tests/filesys/base/sm-full.d \
./src/tests/filesys/base/sm-random.d \
./src/tests/filesys/base/sm-seq-block.d \
./src/tests/filesys/base/sm-seq-random.d \
./src/tests/filesys/base/syn-read.d \
./src/tests/filesys/base/syn-remove.d \
./src/tests/filesys/base/syn-write.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/filesys/base/%.o: ../src/tests/filesys/base/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


