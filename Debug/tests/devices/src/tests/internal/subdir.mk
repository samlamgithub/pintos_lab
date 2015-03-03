################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tests/devices/src/tests/internal/list.c \
../tests/devices/src/tests/internal/stdio.c \
../tests/devices/src/tests/internal/stdlib.c 

OBJS += \
./tests/devices/src/tests/internal/list.o \
./tests/devices/src/tests/internal/stdio.o \
./tests/devices/src/tests/internal/stdlib.o 

C_DEPS += \
./tests/devices/src/tests/internal/list.d \
./tests/devices/src/tests/internal/stdio.d \
./tests/devices/src/tests/internal/stdlib.d 


# Each subdirectory must supply rules for building sources it contributes
tests/devices/src/tests/internal/%.o: ../tests/devices/src/tests/internal/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


