import 'react-native-gesture-handler';
import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import Login from './screens/Login'; 
import Home from './screens/Home'; 
import ForgotPass from './screens/ForgotPassword'; 

import otp from './screens/OTP';
import PasswordSentScreen from './screens/PasswordSentScreen';
import Dashboard from './screens/Dashboard';
import LectureProgressShow from './screens/LectureProgressShow';
import ShowLectureAttendance from './screens/ShowLectureAttendance';
import TabNavigator from './components/TabNavigator';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import OTP from './screens/OTP';
import ChangePass from './screens/ChangePass';
import MessagingScreen from './screens/MessagingScreen';
import ConversationViewScreen from './screens/ConversationViewScreen';
import NewChat from './screens/NewChat';
import NewConversationScreen from './screens/NewConversationScreen';

const Stack = createNativeStackNavigator();

export default function App() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
    <NavigationContainer>
      <Stack.Navigator initialRouteName="Login">
        <Stack.Screen
          name="Login"
          component={Login}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="Dashboard"
          component={Dashboard}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="TabNavigator"
          component={TabNavigator} 
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="ForgotPass"
          component={ForgotPass}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="otp"
          component={OTP}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="OTP"
          component={otp}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="ChangePass"
          component={ChangePass}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="MessagingScreen"
          component={MessagingScreen}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="ConversationViewScreen"
          component={ConversationViewScreen}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="NewChat"
          component={NewChat}
          options={{
            headerShown: false,
          }}
        />
        <Stack.Screen
          name="NewConversationScreen"
          component={NewConversationScreen}
          options={{
            headerShown: false,
          }}
        />
      </Stack.Navigator>
    </NavigationContainer>
    </GestureHandlerRootView>
  );
}
