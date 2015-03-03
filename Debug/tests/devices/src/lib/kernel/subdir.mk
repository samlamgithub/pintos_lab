################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/lib/kernel/bitmap.c \
../tests/devices/src/lib/kernel/console.c \
../tests/devices/src/lib/kernel/debug.c \
../tests/devices/src/lib/kernel/hash.c \
../tests/devices/src/lib/kernel/list.c 

OBJS += \
./tests/devices/src/lib/kernel/bitmap.o \
./tests/devices/src/lib/kernel/console.o \
./tests/devices/src/lib/kernel/debug.o \
./tests/devices/src/lib/kernel/hash.o \
./tests/devices/src/lib/kernel/list.o 

C_DEPS += \
./tests/devices/src/lib/kernel/bitmap.d \
./tests/devices/src/lib/kernel/console.d \
./tests/devices/src/lib/kernel/debug.d \
./tests/devices/src/lib/kernel/hash.d \
./tests/devices/src/lib/kernel/list.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/lib/kernel/%.o: ../tests/devices/src/lib/kernel/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


