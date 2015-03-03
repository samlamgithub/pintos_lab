################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/lib/arithmetic.c \
../tests/devices/src/lib/debug.c \
../tests/devices/src/lib/random.c \
../tests/devices/src/lib/stdio.c \
../tests/devices/src/lib/stdlib.c \
../tests/devices/src/lib/string.c \
../tests/devices/src/lib/ustar.c 

OBJS += \
./tests/devices/src/lib/arithmetic.o \
./tests/devices/src/lib/debug.o \
./tests/devices/src/lib/random.o \
./tests/devices/src/lib/stdio.o \
./tests/devices/src/lib/stdlib.o \
./tests/devices/src/lib/string.o \
./tests/devices/src/lib/ustar.o 

C_DEPS += \
./tests/devices/src/lib/arithmetic.d \
./tests/devices/src/lib/debug.d \
./tests/devices/src/lib/random.d \
./tests/devices/src/lib/stdio.d \
./tests/devices/src/lib/stdlib.d \
./tests/devices/src/lib/string.d \
./tests/devices/src/lib/ustar.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/lib/%.o: ../tests/devices/src/lib/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


