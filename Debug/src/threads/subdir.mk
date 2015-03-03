################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/threads/init.c \
../src/threads/interrupt.c \
../src/threads/malloc.c \
../src/threads/palloc.c \
../src/threads/synch.c \
../src/threads/thread.c 

S_UPPER_SRCS += \
../src/threads/intr-stubs.S \
../src/threads/kernel.lds.S \
../src/threads/loader.S \
../src/threads/start.S \
../src/threads/switch.S 

OBJS += \
./src/threads/init.o \
./src/threads/interrupt.o \
./src/threads/intr-stubs.o \
./src/threads/kernel.lds.o \
./src/threads/loader.o \
./src/threads/malloc.o \
./src/threads/palloc.o \
./src/threads/start.o \
./src/threads/switch.o \
./src/threads/synch.o \
./src/threads/thread.o 

C_DEPS += \
./src/threads/init.d \
./src/threads/interrupt.d \
./src/threads/malloc.d \
./src/threads/palloc.d \
./src/threads/synch.d \
./src/threads/thread.d 


# Each subdirectory must supply rules for building sources it contributes
src/threads/%.o: ../src/threads/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

src/threads/%.o: ../src/threads/%.S
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Assembler'
	as  -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


