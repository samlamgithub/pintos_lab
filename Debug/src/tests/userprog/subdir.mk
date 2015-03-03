################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/userprog/args.c \
../src/tests/userprog/bad-jump.c \
../src/tests/userprog/bad-jump2.c \
../src/tests/userprog/bad-read.c \
../src/tests/userprog/bad-read2.c \
../src/tests/userprog/bad-write.c \
../src/tests/userprog/bad-write2.c \
../src/tests/userprog/boundary.c \
../src/tests/userprog/child-bad.c \
../src/tests/userprog/child-close.c \
../src/tests/userprog/child-rox.c \
../src/tests/userprog/child-simple.c \
../src/tests/userprog/close-bad-fd.c \
../src/tests/userprog/close-normal.c \
../src/tests/userprog/close-stdin.c \
../src/tests/userprog/close-stdout.c \
../src/tests/userprog/close-twice.c \
../src/tests/userprog/create-bad-ptr.c \
../src/tests/userprog/create-bound.c \
../src/tests/userprog/create-empty.c \
../src/tests/userprog/create-exists.c \
../src/tests/userprog/create-long.c \
../src/tests/userprog/create-normal.c \
../src/tests/userprog/create-null.c \
../src/tests/userprog/exec-arg.c \
../src/tests/userprog/exec-bad-ptr.c \
../src/tests/userprog/exec-missing.c \
../src/tests/userprog/exec-multiple.c \
../src/tests/userprog/exec-once.c \
../src/tests/userprog/exit.c \
../src/tests/userprog/halt.c \
../src/tests/userprog/multi-child-fd.c \
../src/tests/userprog/multi-recurse.c \
../src/tests/userprog/open-bad-ptr.c \
../src/tests/userprog/open-boundary.c \
../src/tests/userprog/open-empty.c \
../src/tests/userprog/open-missing.c \
../src/tests/userprog/open-normal.c \
../src/tests/userprog/open-null.c \
../src/tests/userprog/open-twice.c \
../src/tests/userprog/read-bad-fd.c \
../src/tests/userprog/read-bad-ptr.c \
../src/tests/userprog/read-boundary.c \
../src/tests/userprog/read-normal.c \
../src/tests/userprog/read-stdout.c \
../src/tests/userprog/read-zero.c \
../src/tests/userprog/rox-child.c \
../src/tests/userprog/rox-multichild.c \
../src/tests/userprog/rox-simple.c \
../src/tests/userprog/sc-bad-arg.c \
../src/tests/userprog/sc-bad-sp.c \
../src/tests/userprog/sc-boundary-2.c \
../src/tests/userprog/sc-boundary.c \
../src/tests/userprog/wait-bad-pid.c \
../src/tests/userprog/wait-killed.c \
../src/tests/userprog/wait-simple.c \
../src/tests/userprog/wait-twice.c \
../src/tests/userprog/write-bad-fd.c \
../src/tests/userprog/write-bad-ptr.c \
../src/tests/userprog/write-boundary.c \
../src/tests/userprog/write-normal.c \
../src/tests/userprog/write-stdin.c \
../src/tests/userprog/write-zero.c 

OBJS += \
./src/tests/userprog/args.o \
./src/tests/userprog/bad-jump.o \
./src/tests/userprog/bad-jump2.o \
./src/tests/userprog/bad-read.o \
./src/tests/userprog/bad-read2.o \
./src/tests/userprog/bad-write.o \
./src/tests/userprog/bad-write2.o \
./src/tests/userprog/boundary.o \
./src/tests/userprog/child-bad.o \
./src/tests/userprog/child-close.o \
./src/tests/userprog/child-rox.o \
./src/tests/userprog/child-simple.o \
./src/tests/userprog/close-bad-fd.o \
./src/tests/userprog/close-normal.o \
./src/tests/userprog/close-stdin.o \
./src/tests/userprog/close-stdout.o \
./src/tests/userprog/close-twice.o \
./src/tests/userprog/create-bad-ptr.o \
./src/tests/userprog/create-bound.o \
./src/tests/userprog/create-empty.o \
./src/tests/userprog/create-exists.o \
./src/tests/userprog/create-long.o \
./src/tests/userprog/create-normal.o \
./src/tests/userprog/create-null.o \
./src/tests/userprog/exec-arg.o \
./src/tests/userprog/exec-bad-ptr.o \
./src/tests/userprog/exec-missing.o \
./src/tests/userprog/exec-multiple.o \
./src/tests/userprog/exec-once.o \
./src/tests/userprog/exit.o \
./src/tests/userprog/halt.o \
./src/tests/userprog/multi-child-fd.o \
./src/tests/userprog/multi-recurse.o \
./src/tests/userprog/open-bad-ptr.o \
./src/tests/userprog/open-boundary.o \
./src/tests/userprog/open-empty.o \
./src/tests/userprog/open-missing.o \
./src/tests/userprog/open-normal.o \
./src/tests/userprog/open-null.o \
./src/tests/userprog/open-twice.o \
./src/tests/userprog/read-bad-fd.o \
./src/tests/userprog/read-bad-ptr.o \
./src/tests/userprog/read-boundary.o \
./src/tests/userprog/read-normal.o \
./src/tests/userprog/read-stdout.o \
./src/tests/userprog/read-zero.o \
./src/tests/userprog/rox-child.o \
./src/tests/userprog/rox-multichild.o \
./src/tests/userprog/rox-simple.o \
./src/tests/userprog/sc-bad-arg.o \
./src/tests/userprog/sc-bad-sp.o \
./src/tests/userprog/sc-boundary-2.o \
./src/tests/userprog/sc-boundary.o \
./src/tests/userprog/wait-bad-pid.o \
./src/tests/userprog/wait-killed.o \
./src/tests/userprog/wait-simple.o \
./src/tests/userprog/wait-twice.o \
./src/tests/userprog/write-bad-fd.o \
./src/tests/userprog/write-bad-ptr.o \
./src/tests/userprog/write-boundary.o \
./src/tests/userprog/write-normal.o \
./src/tests/userprog/write-stdin.o \
./src/tests/userprog/write-zero.o 

C_DEPS += \
./src/tests/userprog/args.d \
./src/tests/userprog/bad-jump.d \
./src/tests/userprog/bad-jump2.d \
./src/tests/userprog/bad-read.d \
./src/tests/userprog/bad-read2.d \
./src/tests/userprog/bad-write.d \
./src/tests/userprog/bad-write2.d \
./src/tests/userprog/boundary.d \
./src/tests/userprog/child-bad.d \
./src/tests/userprog/child-close.d \
./src/tests/userprog/child-rox.d \
./src/tests/userprog/child-simple.d \
./src/tests/userprog/close-bad-fd.d \
./src/tests/userprog/close-normal.d \
./src/tests/userprog/close-stdin.d \
./src/tests/userprog/close-stdout.d \
./src/tests/userprog/close-twice.d \
./src/tests/userprog/create-bad-ptr.d \
./src/tests/userprog/create-bound.d \
./src/tests/userprog/create-empty.d \
./src/tests/userprog/create-exists.d \
./src/tests/userprog/create-long.d \
./src/tests/userprog/create-normal.d \
./src/tests/userprog/create-null.d \
./src/tests/userprog/exec-arg.d \
./src/tests/userprog/exec-bad-ptr.d \
./src/tests/userprog/exec-missing.d \
./src/tests/userprog/exec-multiple.d \
./src/tests/userprog/exec-once.d \
./src/tests/userprog/exit.d \
./src/tests/userprog/halt.d \
./src/tests/userprog/multi-child-fd.d \
./src/tests/userprog/multi-recurse.d \
./src/tests/userprog/open-bad-ptr.d \
./src/tests/userprog/open-boundary.d \
./src/tests/userprog/open-empty.d \
./src/tests/userprog/open-missing.d \
./src/tests/userprog/open-normal.d \
./src/tests/userprog/open-null.d \
./src/tests/userprog/open-twice.d \
./src/tests/userprog/read-bad-fd.d \
./src/tests/userprog/read-bad-ptr.d \
./src/tests/userprog/read-boundary.d \
./src/tests/userprog/read-normal.d \
./src/tests/userprog/read-stdout.d \
./src/tests/userprog/read-zero.d \
./src/tests/userprog/rox-child.d \
./src/tests/userprog/rox-multichild.d \
./src/tests/userprog/rox-simple.d \
./src/tests/userprog/sc-bad-arg.d \
./src/tests/userprog/sc-bad-sp.d \
./src/tests/userprog/sc-boundary-2.d \
./src/tests/userprog/sc-boundary.d \
./src/tests/userprog/wait-bad-pid.d \
./src/tests/userprog/wait-killed.d \
./src/tests/userprog/wait-simple.d \
./src/tests/userprog/wait-twice.d \
./src/tests/userprog/write-bad-fd.d \
./src/tests/userprog/write-bad-ptr.d \
./src/tests/userprog/write-boundary.d \
./src/tests/userprog/write-normal.d \
./src/tests/userprog/write-stdin.d \
./src/tests/userprog/write-zero.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/userprog/%.o: ../src/tests/userprog/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


