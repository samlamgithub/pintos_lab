################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/tests/arc4.c \
../tests/devices/src/tests/cksum.c \
../tests/devices/src/tests/lib.c \
../tests/devices/src/tests/main.c 

OBJS += \
./tests/devices/src/tests/arc4.o \
./tests/devices/src/tests/cksum.o \
./tests/devices/src/tests/lib.o \
./tests/devices/src/tests/main.o 

C_DEPS += \
./tests/devices/src/tests/arc4.d \
./tests/devices/src/tests/cksum.d \
./tests/devices/src/tests/lib.d \
./tests/devices/src/tests/main.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/tests/%.o: ../tests/devices/src/tests/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


