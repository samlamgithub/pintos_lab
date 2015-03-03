################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/threads/example_thread.c \
../src/tests/threads/mlfqs-block.c \
../src/tests/threads/mlfqs-fair.c \
../src/tests/threads/mlfqs-load-1.c \
../src/tests/threads/mlfqs-load-60.c \
../src/tests/threads/mlfqs-load-avg.c \
../src/tests/threads/mlfqs-recent-1.c \
../src/tests/threads/priority-change.c \
../src/tests/threads/priority-condvar.c \
../src/tests/threads/priority-donate-chain.c \
../src/tests/threads/priority-donate-lower.c \
../src/tests/threads/priority-donate-multiple.c \
../src/tests/threads/priority-donate-multiple2.c \
../src/tests/threads/priority-donate-nest.c \
../src/tests/threads/priority-donate-one.c \
../src/tests/threads/priority-donate-sema.c \
../src/tests/threads/priority-fifo.c \
../src/tests/threads/priority-preempt.c \
../src/tests/threads/priority-sema.c \
../src/tests/threads/tests.c 

OBJS += \
./src/tests/threads/example_thread.o \
./src/tests/threads/mlfqs-block.o \
./src/tests/threads/mlfqs-fair.o \
./src/tests/threads/mlfqs-load-1.o \
./src/tests/threads/mlfqs-load-60.o \
./src/tests/threads/mlfqs-load-avg.o \
./src/tests/threads/mlfqs-recent-1.o \
./src/tests/threads/priority-change.o \
./src/tests/threads/priority-condvar.o \
./src/tests/threads/priority-donate-chain.o \
./src/tests/threads/priority-donate-lower.o \
./src/tests/threads/priority-donate-multiple.o \
./src/tests/threads/priority-donate-multiple2.o \
./src/tests/threads/priority-donate-nest.o \
./src/tests/threads/priority-donate-one.o \
./src/tests/threads/priority-donate-sema.o \
./src/tests/threads/priority-fifo.o \
./src/tests/threads/priority-preempt.o \
./src/tests/threads/priority-sema.o \
./src/tests/threads/tests.o 

C_DEPS += \
./src/tests/threads/example_thread.d \
./src/tests/threads/mlfqs-block.d \
./src/tests/threads/mlfqs-fair.d \
./src/tests/threads/mlfqs-load-1.d \
./src/tests/threads/mlfqs-load-60.d \
./src/tests/threads/mlfqs-load-avg.d \
./src/tests/threads/mlfqs-recent-1.d \
./src/tests/threads/priority-change.d \
./src/tests/threads/priority-condvar.d \
./src/tests/threads/priority-donate-chain.d \
./src/tests/threads/priority-donate-lower.d \
./src/tests/threads/priority-donate-multiple.d \
./src/tests/threads/priority-donate-multiple2.d \
./src/tests/threads/priority-donate-nest.d \
./src/tests/threads/priority-donate-one.d \
./src/tests/threads/priority-donate-sema.d \
./src/tests/threads/priority-fifo.d \
./src/tests/threads/priority-preempt.d \
./src/tests/threads/priority-sema.d \
./src/tests/threads/tests.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/threads/%.o: ../src/tests/threads/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


