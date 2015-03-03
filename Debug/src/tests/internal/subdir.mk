################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tests/internal/list.c \
../src/tests/internal/stdio.c \
../src/tests/internal/stdlib.c 

OBJS += \
./src/tests/internal/list.o \
./src/tests/internal/stdio.o \
./src/tests/internal/stdlib.o 

C_DEPS += \
./src/tests/internal/list.d \
./src/tests/internal/stdio.d \
./src/tests/internal/stdlib.d 


# Each subdirectory must supply rules for building sources it contributes
src/tests/internal/%.o: ../src/tests/internal/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


