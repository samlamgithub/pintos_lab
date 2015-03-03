################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/lib/user/console.c \
../tests/devices/src/lib/user/debug.c \
../tests/devices/src/lib/user/entry.c \
../tests/devices/src/lib/user/syscall.c 

OBJS += \
./tests/devices/src/lib/user/console.o \
./tests/devices/src/lib/user/debug.o \
./tests/devices/src/lib/user/entry.o \
./tests/devices/src/lib/user/syscall.o 

C_DEPS += \
./tests/devices/src/lib/user/console.d \
./tests/devices/src/lib/user/debug.d \
./tests/devices/src/lib/user/entry.d \
./tests/devices/src/lib/user/syscall.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/lib/user/%.o: ../tests/devices/src/lib/user/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


